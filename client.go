package efundpay

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	MerchantAccountID     string
	JWTKeyID              string
	RSAPrivateKey         string
	Environment           string
	BaseURL               string
	Issuer                string
	Scopes                []string
	TokenTTL              time.Duration
	TokenClockSkewSeconds int64
}

func ConfigFromEnv() (Config, error) {
	merchantAccountID := os.Getenv("EFUNDPAY_MERCHANT_ACCOUNT_ID")
	jwtKeyID := os.Getenv("EFUNDPAY_JWT_KEY_ID")
	privateKey := os.Getenv("EFUNDPAY_RSA_PRIVATE_KEY")
	if merchantAccountID == "" {
		return Config{}, errors.New("EFUNDPAY_MERCHANT_ACCOUNT_ID is required")
	}
	if jwtKeyID == "" {
		return Config{}, errors.New("EFUNDPAY_JWT_KEY_ID is required")
	}
	if privateKey == "" {
		return Config{}, errors.New("EFUNDPAY_RSA_PRIVATE_KEY is required")
	}
	return Config{
		MerchantAccountID: merchantAccountID,
		JWTKeyID:          jwtKeyID,
		RSAPrivateKey:     privateKey,
		Environment:       getenvDefault("EFUNDPAY_ENVIRONMENT", "sandbox"),
		BaseURL:           os.Getenv("EFUNDPAY_BASE_URL"),
	}, nil
}

type Client struct {
	config     Config
	httpClient *http.Client
}

type RequestOptions struct {
	Query          map[string]any
	IdempotencyKey string
	ForwardedFor   string
	Scope          string
	ExtraHeaders   map[string]string
}

type TokenOptions struct {
	Scopes      []string
	ExtraClaims map[string]any
	Now         time.Time
	JTI         string
}

type APIError struct {
	StatusCode int
	Response   any
}

func (e *APIError) Error() string {
	return fmt.Sprintf("EFundPay API error %d", e.StatusCode)
}

func NewClient(config Config, httpClient *http.Client) (*Client, error) {
	if config.Environment == "" {
		config.Environment = "sandbox"
	}
	if config.Issuer == "" {
		config.Issuer = "efundpay-go-sdk"
	}
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"*.read", "*.write"}
	}
	if config.TokenTTL == 0 {
		config.TokenTTL = time.Hour
	}
	if config.TokenClockSkewSeconds == 0 {
		config.TokenClockSkewSeconds = 60
	}
	if _, err := config.resolvedBaseURL(); err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{config: config, httpClient: httpClient}, nil
}

func (c *Client) CreateJWT(scopes []string) (string, error) {
	return c.CreateJWTWithOptions(TokenOptions{Scopes: scopes})
}

func (c *Client) CreateJWTWithOptions(options TokenOptions) (string, error) {
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	nowSeconds := now.Unix()
	tokenScopes := options.Scopes
	if len(tokenScopes) == 0 {
		tokenScopes = c.config.Scopes
	}
	jti := options.JTI
	if jti == "" {
		jti = newJTI()
	}

	header := map[string]any{"typ": "JWT", "alg": "RS512", "kid": c.config.JWTKeyID}
	claims := map[string]any{
		"iss":        c.config.Issuer,
		"nbf":        nowSeconds - c.config.TokenClockSkewSeconds,
		"exp":        nowSeconds + int64(c.config.TokenTTL.Seconds()),
		"iat":        nowSeconds,
		"jti":        jti,
		"scopes":     tokenScopes,
		"merchantId": c.config.MerchantAccountID,
	}
	for key, value := range options.ExtraClaims {
		if value != nil {
			claims[key] = value
		}
	}

	encodedHeader, err := base64URLJSON(header)
	if err != nil {
		return "", err
	}
	encodedClaims, err := base64URLJSON(claims)
	if err != nil {
		return "", err
	}
	signingInput := encodedHeader + "." + encodedClaims
	privateKey, err := parseRSAPrivateKey(c.config.RSAPrivateKey)
	if err != nil {
		return "", err
	}
	digest := sha512.Sum512([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (c *Client) Request(ctx context.Context, method string, path string, body any, options *RequestOptions) (any, error) {
	if options == nil {
		options = &RequestOptions{}
	}
	baseURL, err := c.config.resolvedBaseURL()
	if err != nil {
		return nil, err
	}
	requestURL, err := url.Parse(joinURL(baseURL, path))
	if err != nil {
		return nil, err
	}
	if len(options.Query) > 0 {
		values := requestURL.Query()
		for key, value := range options.Query {
			appendQueryValue(values, key, value)
		}
		requestURL.RawQuery = values.Encode()
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), requestURL.String(), reader)
	if err != nil {
		return nil, err
	}
	tokenScopes := []string(nil)
	if options.Scope != "" {
		tokenScopes = []string{options.Scope}
	}
	token, err := c.CreateJWT(tokenScopes)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("x-merchant-account-id", c.config.MerchantAccountID)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if options.IdempotencyKey != "" {
		req.Header.Set("idempotency-key", options.IdempotencyKey)
	}
	if options.ForwardedFor != "" {
		req.Header.Set("X-Forwarded-For", options.ForwardedFor)
	}
	for key, value := range options.ExtraHeaders {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	decoded, err := decodeResponse(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, &APIError{StatusCode: resp.StatusCode, Response: decoded}
	}
	return decoded, nil
}

func (c *Client) CreatePayment(ctx context.Context, payload map[string]any, options *RequestOptions) (any, error) {
	return c.Request(ctx, http.MethodPost, "/v4/transactions/payments", payload, withScope(options, "transactions.write"))
}

func (c *Client) CreateTransaction(ctx context.Context, payload map[string]any, options *RequestOptions) (any, error) {
	return c.Request(ctx, http.MethodPost, "/v4/transactions", payload, withScope(options, "transactions.write"))
}

func (c *Client) CreateCheckoutPayment(ctx context.Context, payload map[string]any, options *RequestOptions) (any, error) {
	return c.Request(ctx, http.MethodPost, "/v4/checkout/payments", payload, withScope(options, "transactions.write"))
}

func (c *Client) CreatePaymentRequest(ctx context.Context, payload map[string]any, options *RequestOptions) (any, error) {
	return c.CreateCheckoutPayment(ctx, payload, options)
}

func (c *Client) ListTransactions(ctx context.Context, query map[string]any) (any, error) {
	return c.Request(ctx, http.MethodGet, "/v4/transactions", nil, &RequestOptions{Query: query, Scope: "transactions.read"})
}

func (c *Client) GetTransaction(ctx context.Context, transactionID string) (any, error) {
	return c.Request(ctx, http.MethodGet, "/v4/transactions/"+url.PathEscape(transactionID), nil, &RequestOptions{Scope: "transactions.read"})
}

func (c *Client) CreateRefund(ctx context.Context, transactionID string, payload map[string]any, options *RequestOptions) (any, error) {
	path := "/v4/transactions/" + url.PathEscape(transactionID) + "/refunds"
	return c.Request(ctx, http.MethodPost, path, payload, withScope(options, "transactions.write"))
}

func (c *Client) CreateRefundRequest(ctx context.Context, transactionID string, payload map[string]any, options *RequestOptions) (any, error) {
	return c.CreateRefund(ctx, transactionID, payload, options)
}

func (c *Client) ListRefunds(ctx context.Context, transactionID string, query map[string]any) (any, error) {
	path := "/v4/transactions/" + url.PathEscape(transactionID) + "/refunds"
	return c.Request(ctx, http.MethodGet, path, nil, &RequestOptions{Query: query, Scope: "transactions.read"})
}

func (c *Client) GetRefund(ctx context.Context, refundID string) (any, error) {
	return c.Request(ctx, http.MethodGet, "/v4/refunds/"+url.PathEscape(refundID), nil, &RequestOptions{Scope: "transactions.read"})
}

func (c *Client) CreateShipment(ctx context.Context, transactionID string, payload map[string]any, options *RequestOptions) (any, error) {
	path := "/v4/transactions/" + url.PathEscape(transactionID) + "/shipments"
	return c.Request(ctx, http.MethodPost, path, payload, withScope(options, "shipments.write"))
}

func (c *Client) ListChargebacks(ctx context.Context, query map[string]any) (any, error) {
	return c.Request(ctx, http.MethodGet, "/v4/chargebacks", nil, &RequestOptions{Query: query, Scope: "chargebacks.read"})
}

func (c *Client) SubmitPreDisputeOutcome(ctx context.Context, alertID string, payload map[string]any, signature string) (any, error) {
	path := "/v4/risk/preDispute/" + url.PathEscape(alertID) + "/outcome"
	return c.Request(ctx, http.MethodPost, path, payload, &RequestOptions{
		Scope:        "pre-dispute.write",
		ExtraHeaders: map[string]string{"signature": signature},
	})
}

func (c *Client) CreatePaymentToken(ctx context.Context, payload map[string]any, options *RequestOptions) (any, error) {
	return c.Request(ctx, http.MethodPost, "/v4/tokens", payload, withScope(options, "subscriptions.write"))
}

func (c *Client) CreateTokenPayment(ctx context.Context, tokenID string, payload map[string]any, options *RequestOptions) (any, error) {
	path := "/v4/tokens/" + url.PathEscape(tokenID) + "/payment"
	return c.Request(ctx, http.MethodPost, path, payload, withScope(options, "subscriptions.write"))
}

func (c *Client) CreateSubscription(ctx context.Context, payload map[string]any, options *RequestOptions) (any, error) {
	return c.Request(ctx, http.MethodPost, "/v4/subscriptions", payload, withScope(options, "subscriptions.write"))
}

func (c *Client) ListSubscriptions(ctx context.Context, query map[string]any) (any, error) {
	return c.Request(ctx, http.MethodGet, "/v4/subscriptions", nil, &RequestOptions{Query: query, Scope: "subscriptions.read"})
}

func (c *Client) GetSubscription(ctx context.Context, subscriptionID string) (any, error) {
	return c.Request(ctx, http.MethodGet, "/v4/subscriptions/"+url.PathEscape(subscriptionID), nil, &RequestOptions{Scope: "subscriptions.read"})
}

func (c *Client) UpdateSubscription(ctx context.Context, subscriptionID string, payload map[string]any, options *RequestOptions) (any, error) {
	path := "/v4/subscriptions/" + url.PathEscape(subscriptionID)
	return c.Request(ctx, http.MethodPost, path, payload, withScope(options, "subscriptions.write"))
}

func (c *Client) UpdateSubscriptionStatus(ctx context.Context, subscriptionID string, payload map[string]any, options *RequestOptions) (any, error) {
	path := "/v4/subscriptions/" + url.PathEscape(subscriptionID) + "/status"
	return c.Request(ctx, http.MethodPost, path, payload, withScope(options, "subscriptions.write"))
}

func GenerateSignatureString(payload any) (string, error) {
	var data any
	switch value := payload.(type) {
	case string:
		if err := json.Unmarshal([]byte(value), &data); err != nil {
			return "", err
		}
	case []byte:
		if err := json.Unmarshal(value, &data); err != nil {
			return "", err
		}
	default:
		data = value
	}
	parts := make([]string, 0)
	appendSignatureParts(&parts, data)
	return strings.Join(parts, "&"), nil
}

func SignWebhookPayload(payload any, privateKeyPEM string) (string, error) {
	content, err := GenerateSignatureString(payload)
	if err != nil {
		return "", err
	}
	privateKey, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	digest := sha1.Sum([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func VerifyWebhookSignature(payload any, signatures any, publicKeyPEM string) bool {
	content, err := GenerateSignatureString(payload)
	if err != nil {
		return false
	}
	publicKey, err := parseRSAPublicKey(publicKeyPEM)
	if err != nil {
		return false
	}
	candidates := []string{}
	switch value := signatures.(type) {
	case string:
		candidates = strings.Split(value, ",")
	case []string:
		candidates = value
	default:
		return false
	}
	digest := sha1.Sum([]byte(content))
	for _, candidate := range candidates {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(candidate))
		if err == nil && rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, digest[:], raw) == nil {
			return true
		}
	}
	return false
}

func (c Config) resolvedBaseURL() (string, error) {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/"), nil
	}
	switch c.Environment {
	case "", "sandbox":
		return "https://sandbox.efundpay.com", nil
	case "production":
		return "https://api.efundpay.com", nil
	default:
		return "", errors.New("environment must be 'sandbox' or 'production'")
	}
}

func base64URLJSON(data any) (string, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func parseRSAPrivateKey(key string) (*rsa.PrivateKey, error) {
	der, err := keyDER(key, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		if privateKey, ok := parsed.(*rsa.PrivateKey); ok {
			return privateKey, nil
		}
		return nil, errors.New("private key is not RSA")
	}
	if privateKey, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return privateKey, nil
	}
	return nil, err
}

func parseRSAPublicKey(key string) (*rsa.PublicKey, error) {
	der, err := keyDER(key, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err == nil {
		if publicKey, ok := parsed.(*rsa.PublicKey); ok {
			return publicKey, nil
		}
		return nil, errors.New("public key is not RSA")
	}
	if publicKey, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return publicKey, nil
	}
	return nil, err
}

func keyDER(key string, defaultType string) ([]byte, error) {
	normalized := strings.TrimSpace(strings.ReplaceAll(key, `\n`, "\n"))
	if block, _ := pem.Decode([]byte(normalized)); block != nil {
		return block.Bytes, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", defaultType, err)
	}
	return decoded, nil
}

func decodeResponse(reader io.Reader) (any, error) {
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, nil
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return string(body), nil
	}
	return decoded, nil
}

func appendSignatureParts(parts *[]string, value any) {
	obj, ok := value.(map[string]any)
	if !ok {
		return
	}
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		item := obj[key]
		switch typed := item.(type) {
		case map[string]any:
			appendSignatureParts(parts, typed)
		case []any:
			for _, child := range typed {
				appendSignatureParts(parts, child)
			}
		case string:
			*parts = append(*parts, key+"="+typed)
		case bool:
			*parts = append(*parts, key+"="+strconv.FormatBool(typed))
		case int:
			*parts = append(*parts, key+"="+strconv.Itoa(typed))
		case int64:
			*parts = append(*parts, key+"="+strconv.FormatInt(typed, 10))
		case float64:
			*parts = append(*parts, key+"="+formatFloat(typed))
		case json.Number:
			*parts = append(*parts, key+"="+typed.String())
		}
	}
}

func formatFloat(value float64) string {
	if math.Trunc(value) == value {
		return strconv.FormatInt(int64(value), 10)
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func appendQueryValue(values url.Values, key string, value any) {
	if value == nil {
		return
	}
	switch typed := value.(type) {
	case []string:
		for _, item := range typed {
			values.Add(key, item)
		}
	case []any:
		for _, item := range typed {
			values.Add(key, fmt.Sprint(item))
		}
	default:
		values.Set(key, fmt.Sprint(value))
	}
}

func withScope(options *RequestOptions, scope string) *RequestOptions {
	if options == nil {
		return &RequestOptions{Scope: scope}
	}
	copy := *options
	copy.Scope = scope
	return &copy
}

func joinURL(baseURL string, path string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
}

func getenvDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func newJTI() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:])
}
