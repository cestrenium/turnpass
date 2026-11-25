package solver

import (
	"context"
	"testing"
	"time"

	"github.com/cestrenium/turnpass/internal/browserprofile"
	tperr "github.com/cestrenium/turnpass/internal/errors"
)

func mustBrowser(t *testing.T) *browserprofile.Browser {
	t.Helper()
	b, err := browserprofile.FromJSON([]byte(`{
  "engine": "chromium",
  "transport": {"profile": "chrome", "platform": "desktop", "headers": {"User-Agent": "Test/1"}, "requests": {"headers": {"navigation": ["user-agent"]}}},
  "timeline": {}, "intervals": {}, "orchestrator": {}, "resource_timing": {}, "interaction": {}, "second": {}
}`), nil, nil)
	if err != nil {
		t.Fatalf("FromJSON: %v", err)
	}
	return b
}

func TestSolveTurnstileRequiresURL(t *testing.T) {
	s := New(mustBrowser(t))
	_, err := s.SolveTurnstile(context.Background(), Turnstile{}, Options{Timeout: time.Second})
	if err == nil {
		t.Fatal("expected error")
	}
	var e *tperr.Error
	if !errorAs(err, &e) || e.Category != tperr.CategoryConfig {
		t.Errorf("err = %v, want Config", err)
	}
}

func TestSolveTurnstileBlankRequiresWidget(t *testing.T) {
	s := New(mustBrowser(t))
	_, err := s.SolveTurnstile(context.Background(), Turnstile{URL: "https://x.com/", Page: PageBlank}, Options{Timeout: time.Second})
	if err == nil {
		t.Fatal("expected error")
	}
	var e *tperr.Error
	if !errorAs(err, &e) || e.Category != tperr.CategoryConfig {
		t.Errorf("err = %v, want Config", err)
	}
}

func TestSolveTurnstileNoWidget(t *testing.T) {
	s := New(mustBrowser(t))
	_, err := s.SolveTurnstile(context.Background(), Turnstile{URL: "https://example.com/", Page: PageHTML, HTML: "<html><body>no widget</body></html>"}, Options{Timeout: 5 * time.Second})
	if err == nil {
		t.Fatal("expected error")
	}
	var e *tperr.Error
	if !errorAs(err, &e) || e.Category != tperr.CategoryUnsupported {
		t.Errorf("err = %v, want Unsupported", err)
	}
}

func TestClearRequiresURL(t *testing.T) {
	s := New(mustBrowser(t))
	_, err := s.Clear(context.Background(), "", Options{Timeout: time.Second})
	if err == nil {
		t.Fatal("expected error")
	}
	var e *tperr.Error
	if !errorAs(err, &e) || e.Category != tperr.CategoryConfig {
		t.Errorf("err = %v, want Config", err)
	}
}

// errorAs wraps errors.As so tests can avoid importing the errors package
// under its aliased name.
func errorAs(err error, target any) bool {
	return errorsAs(err, target)
}
