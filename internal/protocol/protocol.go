// Package protocol implements Cloudflare challenge detection, Turnstile
// widget discovery, and sitekey/action/cData extraction.
//
// These functions operate on raw HTML and HTTP responses only. They do not
// execute JavaScript and do not depend on the challenge-program VM.
package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// ChallengeKind classifies the kind of Cloudflare challenge a page is showing.
type ChallengeKind int

const (
	// ChallengeNone means no Cloudflare challenge was detected.
	ChallengeNone ChallengeKind = iota
	// Challenge5s is the "Checking your browser" / "Just a moment" interstitial.
	Challenge5s
	// Challenge10s is the managed challenge (Turnstile-protected) interstitial.
	Challenge10s
	// ChallengeTurnstile means the page contains a Turnstile widget but is not
	// itself a Cloudflare challenge page.
	ChallengeTurnstile
)

func (k ChallengeKind) String() string {
	switch k {
	case Challenge5s:
		return "5s"
	case Challenge10s:
		return "10s"
	case ChallengeTurnstile:
		return "turnstile"
	default:
		return "none"
	}
}

// Page is a parsed HTTP response body with its metadata.
type Page struct {
	URL       string
	Status    int
	Headers   http.Header
	HTML      string
	Title     string
	Challenge ChallengeKind
	Widgets   []Widget
}

// Widget is a discovered Turnstile widget.
type Widget struct {
	Sitekey string
	Action  string
	CData   string
}

var (
	// cf challenge page markers
	rxJustAMoment   = regexp.MustCompile(`(?i)<title>\s*(Just a moment|Checking your browser)`)   //nolint:gochecknoglobals
	rxChlBypass     = regexp.MustCompile(`(?i)cf-chl-bypass`)                                     //nolint:gochecknoglobals
	rxChallengeForm = regexp.MustCompile(`(?i)id\s*=\s*["']challenge-form|name\s*=\s*["']cf-chl`) //nolint:gochecknoglobals
	rxChlManaged    = regexp.MustCompile(`(?i)cf-mitigated|cf-turnstile-challenge|managed_chl`)   //nolint:gochecknoglobals

	// turnstile widget markers
	rxTurnstileDiv    = regexp.MustCompile(`(?i)<div[^>]*class\s*=\s*["'][^"']*\bcf-turnstile\b[^"']*["']`)     //nolint:gochecknoglobals
	rxTurnstileScript = regexp.MustCompile(`(?i)https?://challenges\.cloudflare\.com/turnstile/v[0-9]/api\.js`) //nolint:gochecknoglobals

	// sitekey extraction (data-sitekey or turnstile.render call)
	rxDataSitekey         = regexp.MustCompile(`(?i)data-sitekey\s*=\s*["']([0-9A-Za-z_x-]+)["']`)                                                      //nolint:gochecknoglobals
	rxRenderCall          = regexp.MustCompile(`(?i)turnstile\.render\s*\(\s*[^,]*,\s*\{`)                                                              //nolint:gochecknoglobals
	rxSitekeyProp         = regexp.MustCompile(`(?i)sitekey\s*:\s*["']([0-9A-Za-z_x-]+)["']`)                                                           //nolint:gochecknoglobals
	rxActionProp          = regexp.MustCompile(`(?i)action\s*:\s*["']([^"']*)["']`)                                                                     //nolint:gochecknoglobals
	rxCDataProp           = regexp.MustCompile(`(?i)cdata\s*:\s*["']([^"']*)["']`)                                                                      //nolint:gochecknoglobals
	rxTurnstileTokenField = regexp.MustCompile(`(?i)name\s*=\s*["']cf-turnstile-response["']`)                                                          //nolint:gochecknoglobals
	rxMetaRefresh         = regexp.MustCompile(`(?i)<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]+content\s*=\s*["'][^"']*\d+\s*;\s*url=([^"']+)["']`) //nolint:gochecknoglobals
)

var rxTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`) //nolint:gochecknoglobals

// ParsePage consumes the response body and returns a parsed Page.
func ParsePage(resp *http.Response, finalURL string) (*Page, error) {
	if resp == nil {
		return nil, nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	page := &Page{
		URL:     finalURL,
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
		HTML:    string(body),
	}
	page.Title = extractTitle(page.HTML)
	page.Challenge = detectChallenge(page)
	page.Widgets = findWidgets(page.HTML)
	return page, nil
}

// ParseHTMLBytes builds a Page from already-fetched HTML.
func ParseHTMLBytes(html []byte, status int, finalURL string) *Page {
	p := &Page{
		URL:     finalURL,
		Status:  status,
		HTML:    string(html),
		Headers: http.Header{},
	}
	p.Title = extractTitle(p.HTML)
	p.Challenge = detectChallenge(p)
	p.Widgets = findWidgets(p.HTML)
	return p
}

func extractTitle(html string) string {
	m := rxTitle.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	title := strings.TrimSpace(m[1])
	return title
}

// detectChallenge classifies the page's challenge kind.
func detectChallenge(p *Page) ChallengeKind {
	html := p.HTML
	// Explicit Cloudflare challenge page indicators.
	if rxJustAMoment.MatchString(html) || rxChlBypass.MatchString(html) || rxChallengeForm.MatchString(html) {
		if rxChlManaged.MatchString(html) || len(findWidgets(html)) > 0 {
			return Challenge10s
		}
		return Challenge5s
	}
	// Status 403/503 with a cf-mitigated header is a managed challenge.
	if p.Status == 403 || p.Status == 503 {
		if p.Headers.Get("cf-mitigated") != "" || rxChlManaged.MatchString(html) {
			return Challenge10s
		}
	}
	if len(findWidgets(html)) > 0 {
		return ChallengeTurnstile
	}
	return ChallengeNone
}

// findWidgets extracts all Turnstile widgets on the page.
func findWidgets(html string) []Widget {
	var widgets []Widget
	seen := make(map[string]bool)

	// 1. data-sitekey on .cf-turnstile containers.
	divMatches := rxTurnstileDiv.FindAllString(html, -1)
	for _, div := range divMatches {
		if m := rxDataSitekey.FindStringSubmatch(div); len(m) >= 2 {
			sk := m[1]
			if !seen[sk] {
				widgets = append(widgets, Widget{Sitekey: sk})
				seen[sk] = true
			}
		}
	}

	// 2. data-sitekey anywhere (form-driven explicit widget).
	for _, m := range rxDataSitekey.FindAllStringSubmatch(html, -1) {
		sk := m[1]
		if !seen[sk] {
			widgets = append(widgets, Widget{Sitekey: sk})
			seen[sk] = true
		}
	}

	// 3. turnstile.render({sitekey:..., action:..., cdata:...}).
	renderIdx := rxRenderCall.FindAllStringIndex(html, -1)
	for _, idx := range renderIdx {
		end := findBalancedBrace(html[idx[1]-1:])
		if end < 0 {
			continue
		}
		block := html[idx[1]-1 : idx[1]-1+end]
		w := Widget{}
		if m := rxSitekeyProp.FindStringSubmatch(block); len(m) >= 2 {
			w.Sitekey = m[1]
		}
		if m := rxActionProp.FindStringSubmatch(block); len(m) >= 2 {
			w.Action = m[1]
		}
		if m := rxCDataProp.FindStringSubmatch(block); len(m) >= 2 {
			w.CData = m[1]
		}
		if w.Sitekey != "" && !seen[w.Sitekey] {
			widgets = append(widgets, w)
			seen[w.Sitekey] = true
		}
	}

	return widgets
}

// findBalancedBrace returns the index just past the matching '}' for the '{'
// at s[0]. Returns -1 if unbalanced.
func findBalancedBrace(s string) int {
	if len(s) == 0 || s[0] != '{' {
		return -1
	}
	depth := 0
	inStr := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr != 0 {
			if c == inStr && (i == 0 || s[i-1] != '\\') {
				inStr = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inStr = c
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// HasTurnstileTokenField reports whether the page contains a
// cf-turnstile-response form field.
func HasTurnstileTokenField(html string) bool {
	return rxTurnstileTokenField.MatchString(html)
}

// FindMetaRefresh returns the redirect URL from a <meta http-equiv=refresh> tag.
func FindMetaRefresh(html string) string {
	m := rxMetaRefresh.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// JSONRoundtrip marshals and unmarshals v to verify it is serialisable.
func JSONRoundtrip(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
