package efundpay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type recordedRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}

type fakeRoundTripper struct {
	requests []recordedRequest
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	f.requests = append(f.requests, recordedRequest{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: req.Header.Clone(),
		Body:    body,
	})
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Header:     make(http.Header),
	}, nil
}

func testKeys(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	return privatePEM, publicPEM
}

func testClient(t *testing.T) (*Client, *fakeRoundTripper, string, string) {
	t.Helper()
	privatePEM, publicPEM := testKeys(t)
	transport := &fakeRoundTripper{}
	client, err := NewClient(Config{
		MerchantAccountID: "acct_test",
		JWTKeyID:          "kid_test",
		RSAPrivateKey:     privatePEM,
		BaseURL:           "https://unit.test",
	}, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	return client, transport, privatePEM, publicPEM
}

func TestCreateJWTUsesRS512ClaimsAndKID(t *testing.T) {
	client, _, _, _ := testClient(t)
	token, err := client.CreateJWTWithOptions(TokenOptions{
		Scopes: []string{"transactions.read"},
		Now:    time.Unix(1700000000, 0),
		JTI:    "jti-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected three JWT parts")
	}
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var header map[string]any
	var claims map[string]any
	json.Unmarshal(headerJSON, &header)
	json.Unmarshal(claimsJSON, &claims)
	if header["alg"] != "RS512" || header["kid"] != "kid_test" {
		t.Fatalf("unexpected header: %#v", header)
	}
	if claims["merchantId"] != "acct_test" {
		t.Fatalf("unexpected merchantId: %#v", claims)
	}
	if len(parts[2]) < 100 {
		t.Fatalf("expected JWT signature")
	}
}

func TestCreatePaymentSendsExpectedRequest(t *testing.T) {
	client, transport, _, _ := testClient(t)
	payload := map[string]any{"amount": 1299, "currency": "USD", "external_identifier": "order-12345"}
	_, err := client.CreatePayment(context.Background(), payload, &RequestOptions{
		IdempotencyKey: "idem-1",
		ForwardedFor:   "203.0.113.195",
	})
	if err != nil {
		t.Fatal(err)
	}
	last := transport.requests[len(transport.requests)-1]
	if last.Method != "POST" || last.URL != "https://unit.test/v4/transactions/payments" {
		t.Fatalf("unexpected request: %#v", last)
	}
	if last.Headers.Get("x-merchant-account-id") != "acct_test" {
		t.Fatalf("missing merchant header")
	}
	if last.Headers.Get("idempotency-key") != "idem-1" {
		t.Fatalf("missing idempotency header")
	}
	if last.Headers.Get("X-Forwarded-For") != "203.0.113.195" {
		t.Fatalf("missing forwarded header")
	}
	if !strings.HasPrefix(last.Headers.Get("Authorization"), "Bearer ") {
		t.Fatalf("missing authorization header")
	}
	var decoded map[string]any
	if err := json.Unmarshal(last.Body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["external_identifier"] != "order-12345" {
		t.Fatalf("unexpected body: %s", last.Body)
	}
}

func TestCheckoutAndRefundPaths(t *testing.T) {
	client, transport, _, _ := testClient(t)
	client.CreatePaymentRequest(context.Background(), map[string]any{"amount": 100}, nil)
	client.CreateRefundRequest(context.Background(), "txn_1", map[string]any{"amount": 100}, nil)
	client.ListRefunds(context.Background(), "txn_1", map[string]any{"limit": 20, "cursor": nil})
	client.GetRefund(context.Background(), "refund_1")
	count := len(transport.requests)
	expected := []string{
		"https://unit.test/v4/checkout/payments",
		"https://unit.test/v4/transactions/txn_1/refunds",
		"https://unit.test/v4/transactions/txn_1/refunds?limit=20",
		"https://unit.test/v4/refunds/refund_1",
	}
	for i, want := range expected {
		if got := transport.requests[count-4+i].URL; got != want {
			t.Fatalf("url %d got %s want %s", i, got, want)
		}
	}
}

func TestWebhookSignatureGenerationAndVerification(t *testing.T) {
	_, _, privatePEM, publicPEM := testClient(t)
	payload := map[string]any{
		"merchant_transaction_id": "order-1",
		"payment_data": map[string]any{
			"payment_amount": "1.20",
			"payment_status": "PS",
		},
		"ignored_array": []any{"x", "y"},
	}
	content, err := GenerateSignatureString(payload)
	if err != nil {
		t.Fatal(err)
	}
	if content != "merchant_transaction_id=order-1&payment_amount=1.20&payment_status=PS" {
		t.Fatalf("unexpected content: %s", content)
	}
	signature, err := SignWebhookPayload(payload, privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(payload)
	if !VerifyWebhookSignature(string(encoded), signature, publicPEM) {
		t.Fatalf("expected signature to verify")
	}
	_, wrongPublicPEM := testKeys(t)
	if VerifyWebhookSignature(string(encoded), signature, wrongPublicPEM) {
		t.Fatalf("expected wrong key to fail")
	}
}
