package challenge

import (
	"testing"
)

const testChallengePage = `<html><head>
<script nonce="n">(function(){window._cf_chl_opt = {cH: 'token123', cRay: 'ray456', cUPMDTk: "/protected?__cf_chl_tk=answered"};var a = document.createElement('script');a.src = '/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=ray456';if (window.history && window.history.replaceState) {history.replaceState(null, null,"/protected?__cf_chl_rt_tk=loading" + window._cf_chl_opt.cOgUHash);}document.getElementsByTagName('head')[0].appendChild(a);}());</script>
</head><body></body></html>`

func TestParseChallengePage(t *testing.T) {
	cp, err := ParseChallengePage(testChallengePage, "https://example.com/protected")
	if err != nil {
		t.Fatalf("ParseChallengePage: %v", err)
	}
	if cp == nil {
		t.Fatal("expected a ChallengePage, got nil")
	}
	// Check orchestrator URL.
	wantOrch := "https://example.com/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=ray456"
	if cp.Orchestrator != wantOrch {
		t.Errorf("Orchestrator = %q, want %q", cp.Orchestrator, wantOrch)
	}
	// Check loading address.
	wantLoad := "https://example.com/protected?__cf_chl_rt_tk=loading"
	if cp.Loading != wantLoad {
		t.Errorf("Loading = %q, want %q", cp.Loading, wantLoad)
	}
	// Check answered address.
	wantAns := "https://example.com/protected?__cf_chl_tk=answered"
	if cp.Answered != wantAns {
		t.Errorf("Answered = %q, want %q", cp.Answered, wantAns)
	}
	// Check _cf_chl_opt.
	if cp.CfChlOpt["cH"] != "token123" {
		t.Errorf("CfChlOpt[cH] = %q", cp.CfChlOpt["cH"])
	}
	if cp.CfChlOpt["cRay"] != "ray456" {
		t.Errorf("CfChlOpt[cRay] = %q", cp.CfChlOpt["cRay"])
	}
}

func TestParseChallengePageNotChallenge(t *testing.T) {
	html := `<html><body><p>not a challenge</p></body></html>`
	cp, err := ParseChallengePage(html, "https://example.com/")
	if err != nil {
		t.Fatalf("ParseChallengePage: %v", err)
	}
	if cp != nil {
		t.Errorf("expected nil for non-challenge page, got %+v", cp)
	}
}

func TestExtractInlineJavaScript(t *testing.T) {
	html := `<html><head>
<script src="api.js"></script>
<script type="application/json">{"ignored":true}</script>
<script nonce="x">window._cf_chl_opt = {}; if (1 < 2) x = '&amp;';</script>
<script>another();</script>
</head></html>`
	js := ExtractInlineJavaScript(html)
	if !contains(js, "_cf_chl_opt") {
		t.Errorf("expected _cf_chl_opt in inline JS: %q", js)
	}
	if !contains(js, "another()") {
		t.Errorf("expected another() in inline JS: %q", js)
	}
	if contains(js, "ignored") {
		t.Errorf("application/json script should be excluded: %q", js)
	}
	if contains(js, "src") {
		t.Errorf("external script should be excluded: %q", js)
	}
}

func TestExtractInlineJavaScriptPreservesRawText(t *testing.T) {
	html := `<script>if (1 < 2) x = '&amp;';</script>`
	js := ExtractInlineJavaScript(html)
	if !contains(js, "if (1 < 2) x = '&amp;'") {
		t.Errorf("raw text not preserved: %q", js)
	}
}

func TestFindTurnstileLoaderURL(t *testing.T) {
	html := `<html><head>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head></html>`
	url := FindTurnstileLoaderURL(html, "https://example.com/")
	if url != "https://challenges.cloudflare.com/turnstile/v0/api.js" {
		t.Errorf("loader URL = %q", url)
	}
}

func TestFindTurnstileLoaderURLDefault(t *testing.T) {
	html := `<html><body>no script</body></html>`
	url := FindTurnstileLoaderURL(html, "https://example.com/")
	if url != "https://challenges.cloudflare.com/turnstile/v0/api.js" {
		t.Errorf("default loader URL = %q", url)
	}
}

func TestParseLoaderScript(t *testing.T) {
	source := `var x = {ch: "e694063b5082", other: 1};
	function create(a, b, c) { f(a, "g", e.New, c); }`
	info, err := ParseLoaderScript(source)
	if err != nil {
		t.Fatalf("ParseLoaderScript: %v", err)
	}
	if info.Build != "e694063b5082" {
		t.Errorf("Build = %q", info.Build)
	}
	if info.Route != "g" {
		t.Errorf("Route = %q", info.Route)
	}
}

func TestParseLoaderScriptNoBuild(t *testing.T) {
	source := `var x = {other: 1};`
	_, err := ParseLoaderScript(source)
	if err == nil {
		t.Fatal("expected error for missing build hash")
	}
}

func TestBuildIframeURL(t *testing.T) {
	url, err := BuildIframeURL("https://challenges.cloudflare.com/turnstile/v0/api.js", "g", IframeParams{
		WidgetID: "abc12",
		Sitekey:  "0xDEF",
		Theme:    "auto",
		Size:     "normal",
		Language: "en",
	})
	if err != nil {
		t.Fatalf("BuildIframeURL: %v", err)
	}
	if !contains(url, "challenges.cloudflare.com") {
		t.Errorf("URL missing origin: %q", url)
	}
	if !contains(url, "/cdn-cgi/challenge-platform/h/g/turnstile/f/av0/rch/abc12/0xDEF/auto/normal/") {
		t.Errorf("URL missing path: %q", url)
	}
	if !contains(url, "lang=en") {
		t.Errorf("URL missing lang: %q", url)
	}
}

func TestRandomWidgetID(t *testing.T) {
	id := randomWidgetID()
	if len(id) != 5 {
		t.Errorf("widget ID length = %d, want 5", len(id))
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Errorf("widget ID has invalid char %q in %q", c, id)
		}
	}
	id2 := randomWidgetID()
	if id == id2 {
		t.Errorf("widget IDs should differ: %q == %q", id, id2)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
