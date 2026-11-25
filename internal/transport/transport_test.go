package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cestrenium/turnpass/internal/fingerprint"
)

func mustFP(t *testing.T) *fingerprint.Fingerprint {
	t.Helper()
	fp, err := fingerprint.Parse([]byte(`{
  "engine": "chromium",
  "transport": {
    "profile": "chrome",
    "platform": "desktop",
    "headers": {"User-Agent": "TestUA/1.0"},
    "requests": {"headers": {"navigation": ["user-agent"]}}
  },
  "timeline": {}, "intervals": {}, "orchestrator": {},
  "resource_timing": {}, "interaction": {}, "second": {}
}`))
	if err != nil {
		t.Fatalf("fingerprint.Parse: %v", err)
	}
	return fp
}

func TestNewRequiresFingerprint(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("expected error for nil fingerprint")
	}
}

func TestNewBuildsClient(t *testing.T) {
	c, err := New(Config{Fingerprint: mustFP(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.UserAgent() != "TestUA/1.0" {
		t.Errorf("UserAgent = %q", c.UserAgent())
	}
	if c.Engine() != fingerprint.EngineChromium {
		t.Errorf("Engine = %q", c.Engine())
	}
	if c.Jar() == nil {
		t.Error("Jar is nil")
	}
}

func TestDoAgainstTestServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "TestUA/1.0" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Set-Cookie", "sid=abc; Path=/")
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	fp := mustFP(t)
	// Use an insecure trusted root: accept the test server's self-signed cert
	// by setting InsecureSkipVerify via an empty trusted root plus the
	// http.Transport's default. For test purposes we mark the client's TLS
	// config insecure through the fingerprint by setting the platform to test.
	c, err := New(Config{Fingerprint: fp})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Override the http client transport to accept any cert (test-only).
	// The transport is wrapped in a decompressTransport, so we need to
	// access the underlying *http.Transport.
	dt, ok := c.httpClient.Transport.(*decompressTransport)
	if !ok {
		t.Fatalf("expected *decompressTransport, got %T", c.httpClient.Transport)
	}
	baseTransport, ok := dt.base.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport as base, got %T", dt.base)
	}
	baseTransport.TLSClientConfig.InsecureSkipVerify = true
	baseTransport.ForceAttemptHTTP2 = false

	resp, err := c.Get(context.Background(), "navigation", srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Set-Cookie") == "" {
		t.Error("no Set-Cookie")
	}
}

func TestProxySchemeValidation(t *testing.T) {
	_, err := New(Config{Fingerprint: mustFP(t), Proxy: "ftp://example.com:21"})
	if err == nil {
		t.Fatal("expected error for ftp proxy")
	}
}

func TestClientHelloIDMapping(t *testing.T) {
	// Smoke test: both engines should resolve to a known preset.
	if id := clientHelloID(fingerprint.EngineChromium, "chrome"); id.Client == "" {
		t.Error("chromium hello ID is empty")
	}
	if id := clientHelloID(fingerprint.EngineWebKit, "safari_ios_26.2"); id.Client == "" {
		t.Error("webkit hello ID is empty")
	}
}
