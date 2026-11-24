// Integration test: fetch a real Cloudflare challenge page and verify
// the orchestration flow works (page detection, loader fetching, iframe
// construction).
//
// This test is skipped by default. Set TURNPASS_INTEGRATION=1 to run it.
// It requires network access and may be rate-limited by Cloudflare.
//
//go:build integration

package solver

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cestrenium/turnpass/internal/browserprofile"
)

func TestIntegrationCloudflareChallenge(t *testing.T) {
	if os.Getenv("TURNPASS_INTEGRATION") != "1" {
		t.Skip("skipping integration test; set TURNPASS_INTEGRATION=1 to run")
	}

	// Use the cfsolve safari profile if available, otherwise a minimal test profile.
	profilePath := os.Getenv("TURNPASS_PROFILE")
	if profilePath == "" {
		// Use a minimal inline profile.
		b, err := browserprofile.FromJSON([]byte(`{
  "engine": "chromium",
  "transport": {
    "profile": "chrome",
    "platform": "desktop",
    "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
    "requests": {"headers": {"navigation": ["user-agent"], "iframe": ["user-agent"], "script": ["user-agent"], "orchestrator": ["user-agent"]}}
  },
  "timeline": {}, "intervals": {}, "orchestrator": {},
  "resource_timing": {}, "interaction": {}, "second": {}
}`), nil, nil)
		if err != nil {
			t.Fatalf("FromJSON: %v", err)
		}
		s := New(b)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		targetURL := "https://nopecha.com/captcha/cloudflare"
		sink := &testSink{t: t}
		opts := Options{Timeout: 30 * time.Second, Sink: sink}

		// We expect this to return Unsupported (VM not ported) but the
		// orchestration should complete and log progress.
		_, err = s.Solve(ctx, targetURL, opts)
		if err == nil {
			t.Log("solve succeeded unexpectedly")
		}
		t.Logf("solve returned: %v", err)
		t.Logf("progress messages: %v", sink.messages)
		return
	}

	b, err := browserprofile.Read(profilePath)
	if err != nil {
		t.Fatalf("Read profile: %v", err)
	}
	s := New(b)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	targetURL := "https://nopecha.com/captcha/cloudflare"
	sink := &testSink{t: t}
	opts := Options{Timeout: 60 * time.Second, Sink: sink}

	_, err = s.Solve(ctx, targetURL, opts)
	t.Logf("solve returned: %v", err)
	t.Logf("progress messages: %v", sink.messages)
}

type testSink struct {
	t        *testing.T
	messages []string
}

func (s *testSink) Progress(msg string) {
	s.messages = append(s.messages, msg)
	s.t.Logf("progress: %s", msg)
}

func (s *testSink) Artifact(name string, data []byte) error {
	s.t.Logf("artifact: %s (%d bytes)", name, len(data))
	return nil
}
