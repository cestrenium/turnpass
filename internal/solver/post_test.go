package solver

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cestrenium/turnpass/internal/challenge"
	"github.com/cestrenium/turnpass/internal/fingerprint"
)

func TestPostChallengeSuccess(t *testing.T) {
	// Create a test server that returns a masked response.
	ray := "testray123"
	mask := byte(32)
	for i := 0; i < len(ray); i++ {
		mask ^= ray[i]
	}
	mask ^= '_'
	mask ^= '0'

	// The response is a base64-encoded VM program, masked.
	vmProgram := []byte("hello vm program")
	encodedProgram := base64.StdEncoding.EncodeToString(vmProgram)

	// Mask each byte: (byte + mask + index%65535) % 255
	masked := make([]byte, len(encodedProgram))
	for i, b := range []byte(encodedProgram) {
		masked[i] = byte((int(b) + int(mask) + i%65535) % 255)
	}
	// Base64-encode the masked bytes for the response body.
	responseBody := base64.StdEncoding.EncodeToString(masked)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request headers.
		if r.Header.Get("cf-chl") != "test-token" {
			t.Errorf("cf-chl header = %q", r.Header.Get("cf-chl"))
		}
		if r.Header.Get("cf-chl-ra") != "0" {
			t.Errorf("cf-chl-ra header = %q", r.Header.Get("cf-chl-ra"))
		}
		if r.Header.Get("Content-Type") != "text/plain;charset=UTF-8" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(200)
		w.Write([]byte(responseBody))
	}))
	defer srv.Close()

	// Build a client with a test fingerprint.
	fp, err := fingerprint.Parse([]byte(`{
  "engine": "chromium",
  "transport": {
    "profile": "chrome",
    "platform": "desktop",
    "headers": {"User-Agent": "TestUA/1.0"},
    "requests": {"headers": {"navigation": ["user-agent"], "challenge_post": ["user-agent"]}}
  },
  "timeline": {}, "intervals": {}, "orchestrator": {},
  "resource_timing": {}, "interaction": {}, "second": {}
}`))
	if err != nil {
		t.Fatalf("fingerprint.Parse: %v", err)
	}

	client, err := newTestClient(fp)
	if err != nil {
		t.Fatalf("newTestClient: %v", err)
	}

	initReq := &challenge.InitialRequest{
		URL:   srv.URL,
		CfChl: "test-token",
		Ray:   ray,
	}

	sink := &testPostSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := PostChallenge(ctx, client, initReq, srv.URL, "test-payload", StageInitial, sink)
	if err != nil {
		t.Fatalf("PostChallenge: %v", err)
	}

	if result.Status != 200 {
		t.Errorf("Status = %d, want 200", result.Status)
	}
	if !bytes.Equal(result.Program, vmProgram) {
		t.Errorf("Program = %q, want %q", result.Program, vmProgram)
	}
}

func TestPostChallengeNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	fp, err := fingerprint.Parse([]byte(`{
  "engine": "chromium",
  "transport": {
    "profile": "chrome",
    "platform": "desktop",
    "headers": {"User-Agent": "TestUA/1.0"},
    "requests": {"headers": {"navigation": ["user-agent"], "challenge_post": ["user-agent"]}}
  },
  "timeline": {}, "intervals": {}, "orchestrator": {},
  "resource_timing": {}, "interaction": {}, "second": {}
}`))
	if err != nil {
		t.Fatalf("fingerprint.Parse: %v", err)
	}

	client, err := newTestClient(fp)
	if err != nil {
		t.Fatalf("newTestClient: %v", err)
	}

	initReq := &challenge.InitialRequest{
		URL:   srv.URL,
		CfChl: "test-token",
		Ray:   "testray",
	}

	sink := &testPostSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = PostChallenge(ctx, client, initReq, srv.URL, "test-payload", StageInitial, sink)
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
}

type testPostSink struct {
	messages []string
}

func (s *testPostSink) Progress(msg string) {
	s.messages = append(s.messages, msg)
}

func (s *testPostSink) Artifact(name string, data []byte) error {
	return nil
}
