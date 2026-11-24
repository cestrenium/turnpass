package protocol

import (
	"net/http"
	"testing"
)

func TestExtractTitle(t *testing.T) {
	cases := []struct {
		html string
		want string
	}{
		{"<html><head><title>Hello</title></head></html>", "Hello"},
		{"<TITLE>  Multi  Word </TITLE>", "Multi  Word"},
		{"<html><head></head></html>", ""},
		{"<title>Just a moment...</title>", "Just a moment..."},
	}
	for _, c := range cases {
		if got := extractTitle(c.html); got != c.want {
			t.Errorf("extractTitle(%q) = %q, want %q", c.html, got, c.want)
		}
	}
}

func TestDetectChallenge5s(t *testing.T) {
	html := `<html><head><title>Just a moment...</title></head><body><form id="challenge-form"></form></body></html>`
	p := &Page{HTML: html, Status: 503, Headers: http.Header{}}
	if got := detectChallenge(p); got != Challenge5s {
		t.Errorf("detectChallenge = %s, want 5s", got)
	}
}

func TestDetectChallenge10s(t *testing.T) {
	html := `<html><head><title>Just a moment...</title></head><body>
		<form id="challenge-form"></form>
		<div class="cf-turnstile" data-sitekey="0xABC"></div>
	</body></html>`
	p := &Page{HTML: html, Status: 403, Headers: http.Header{}}
	if got := detectChallenge(p); got != Challenge10s {
		t.Errorf("detectChallenge = %s, want 10s", got)
	}
}

func TestDetectChallengeManagedHeader(t *testing.T) {
	p := &Page{HTML: "<html></html>", Status: 403, Headers: http.Header{"Cf-Mitigated": []string{"challenge"}}}
	if got := detectChallenge(p); got != Challenge10s {
		t.Errorf("detectChallenge = %s, want 10s", got)
	}
}

func TestDetectChallengeTurnstile(t *testing.T) {
	html := `<html><body><div class="cf-turnstile" data-sitekey="0xDEF"></div></body></html>`
	p := &Page{HTML: html, Status: 200, Headers: http.Header{}}
	if got := detectChallenge(p); got != ChallengeTurnstile {
		t.Errorf("detectChallenge = %s, want turnstile", got)
	}
}

func TestFindWidgetsDataSitekey(t *testing.T) {
	html := `<div class="cf-turnstile" data-sitekey="0x123"></div>`
	ws := findWidgets(html)
	if len(ws) != 1 || ws[0].Sitekey != "0x123" {
		t.Errorf("findWidgets = %+v", ws)
	}
}

func TestFindWidgetsRenderCall(t *testing.T) {
	html := `<script>turnstile.render('#c', {sitekey: '0xAAA', action: 'login', cdata: 'session42'});</script>`
	ws := findWidgets(html)
	if len(ws) != 1 {
		t.Fatalf("findWidgets = %+v", ws)
	}
	w := ws[0]
	if w.Sitekey != "0xAAA" || w.Action != "login" || w.CData != "session42" {
		t.Errorf("widget = %+v", w)
	}
}

func TestFindWidgetsDeduplicates(t *testing.T) {
	html := `<div class="cf-turnstile" data-sitekey="0xDUP"></div>
		<script>turnstile.render('#c', {sitekey: '0xDUP'});</script>`
	ws := findWidgets(html)
	if len(ws) != 1 {
		t.Errorf("findWidgets = %+v, want 1", ws)
	}
}

func TestFindMetaRefresh(t *testing.T) {
	html := `<html><head><meta http-equiv="refresh" content="5; url=/next"></head></html>`
	if got := FindMetaRefresh(html); got != "/next" {
		t.Errorf("FindMetaRefresh = %q", got)
	}
}

func TestHasTurnstileTokenField(t *testing.T) {
	if !HasTurnstileTokenField(`<input name="cf-turnstile-response">`) {
		t.Error("HasTurnstileTokenField should be true")
	}
	if HasTurnstileTokenField(`<input name="other">`) {
		t.Error("HasTurnstileTokenField should be false")
	}
}

func TestParseHTMLBytes(t *testing.T) {
	p := ParseHTMLBytes([]byte(`<html><head><title>Hi</title></head><body><div class="cf-turnstile" data-sitekey="0xZZ"></div></body></html>`), 200, "https://example.com/")
	if p.Title != "Hi" {
		t.Errorf("Title = %q", p.Title)
	}
	if p.Challenge != ChallengeTurnstile {
		t.Errorf("Challenge = %s", p.Challenge)
	}
	if len(p.Widgets) != 1 {
		t.Errorf("Widgets = %+v", p.Widgets)
	}
}

func TestFindBalancedBrace(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"{}", 2},
		{"{a:1}", 5},
		{"{a:{b:2}}", 9},
		{"{a:'}'}", 7},
		{"nope", -1},
	}
	for _, c := range cases {
		if got := findBalancedBrace(c.in); got != c.want {
			t.Errorf("findBalancedBrace(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
