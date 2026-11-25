package challenge

import (
	"testing"
)

func TestExtractInitialRequest(t *testing.T) {
	// Test JavaScript that mimics a Turnstile iframe bootstrap script.
	js := `window._cf_chl_opt = {cFPWv: 'b', cH: 'session-token', cRay: 'ray-id-123'};
	(function() {
		var xhr = new XMLHttpRequest();
		xhr.open('POST', '/cdn-cgi/challenge-platform/h/b/fo/build/ray-id-123/session-token');
		xhr.setRequestHeader('cf-chl', 'session-token');
	})();`

	req, err := ExtractInitialRequest(js, "https://challenges.cloudflare.com/iframe")
	if err != nil {
		t.Fatalf("ExtractInitialRequest: %v", err)
	}

	wantURL := "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/fo/build/ray-id-123/session-token"
	if req.URL != wantURL {
		t.Errorf("URL = %q, want %q", req.URL, wantURL)
	}
	if req.CfChl != "session-token" {
		t.Errorf("CfChl = %q, want %q", req.CfChl, "session-token")
	}
	if req.Ray != "ray-id-123" {
		t.Errorf("Ray = %q, want %q", req.Ray, "ray-id-123")
	}
	if req.Options["cH"] != "session-token" {
		t.Errorf("Options[cH] = %q", req.Options["cH"])
	}
}

func TestExtractInitialRequestTokenFromPath(t *testing.T) {
	// Test when the cf-chl header call is not found but the token is in the path.
	js := `window._cf_chl_opt = {};
	xhr.open('POST', '/cdn-cgi/challenge-platform/h/g/fo/v1/myray/mytoken');`

	req, err := ExtractInitialRequest(js, "https://challenges.cloudflare.com/iframe")
	if err != nil {
		t.Fatalf("ExtractInitialRequest: %v", err)
	}
	if req.CfChl != "mytoken" {
		t.Errorf("CfChl = %q, want %q", req.CfChl, "mytoken")
	}
	if req.Ray != "myray" {
		t.Errorf("Ray = %q, want %q", req.Ray, "myray")
	}
}

func TestExtractInitialRequestNoPath(t *testing.T) {
	js := `window._cf_chl_opt = {}; var x = 1;`
	_, err := ExtractInitialRequest(js, "https://challenges.cloudflare.com/iframe")
	if err == nil {
		t.Fatal("expected error for missing POST URL")
	}
}

func TestExtractRay(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/cdn-cgi/challenge-platform/h/g/fo/build/ray-id/token", "ray-id"},
		{"/cdn-cgi/challenge-platform/h/b/fo/v1/myray/mytoken", "myray"},
		{"/no-fo-here", ""},
		{"/cdn-cgi/challenge-platform/h/g/fo/build", ""},
	}
	for _, c := range cases {
		if got := extractRay(c.path); got != c.want {
			t.Errorf("extractRay(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestIsPostPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/cdn-cgi/challenge-platform/h/g/fo/build/ray/token", true},
		{"/cdn-cgi/challenge-platform/h/b/orchestrate/v1", false},
		{"/other/path", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsPostPath(c.path); got != c.want {
			t.Errorf("IsPostPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestParseIframeURL(t *testing.T) {
	origin, err := ParseIframeURL("https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/f/av0/rch/abc/0xDEF/auto/normal/fbD/new?lang=en")
	if err != nil {
		t.Fatalf("ParseIframeURL: %v", err)
	}
	if origin != "https://challenges.cloudflare.com" {
		t.Errorf("origin = %q, want %q", origin, "https://challenges.cloudflare.com")
	}
}
