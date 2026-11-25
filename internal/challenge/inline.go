package challenge

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ScriptTag holds the raw text content of an inline <script> element.
type ScriptTag struct {
	// Text is the raw text content of the script element.
	Text string
	// Src is the value of the src attribute, or empty for inline scripts.
	Src string
	// Type is the value of the type attribute.
	Type string
}

var (
	// Matches <script ...>...</script> blocks, capturing the attributes and the text.
	rxScriptBlock = regexp.MustCompile(`(?is)<script([^>]*)>(.*?)</script>`)
	// Matches src="..." or src='...' within script attributes.
	rxScriptSrc = regexp.MustCompile(`(?i)\ssrc\s*=\s*["']([^"']*)["']`)
	// Matches type="..." within script attributes.
	rxScriptType = regexp.MustCompile(`(?i)\stype\s*=\s*["']([^"']*)["']`)
)

// ExtractInlineJavaScript extracts all inline <script> elements from the HTML
// that have no src attribute and whose type is empty, "text/javascript", or
// "application/javascript". The scripts are joined with "\n;\n".
//
// This mirrors cfsolve's source::inline_javascript function, which uses the
// scraper crate to parse HTML and extract script text.
func ExtractInlineJavaScript(html string) string {
	matches := rxScriptBlock.FindAllStringSubmatch(html, -1)
	var scripts []string
	for _, m := range matches {
		attrs := m[1]
		text := m[2]
		src := extractAttr(attrs, rxScriptSrc)
		scriptType := extractAttr(attrs, rxScriptType)
		if src != "" {
			continue // Skip external scripts.
		}
		if scriptType != "" && scriptType != "text/javascript" && scriptType != "application/javascript" {
			continue // Skip non-JS scripts (e.g., application/json).
		}
		text = strings.TrimSpace(text)
		if text != "" {
			scripts = append(scripts, text)
		}
	}
	return strings.Join(scripts, "\n;\n")
}

// ExtractScriptTags extracts all <script> elements from the HTML, returning
// their src, type, and text content.
func ExtractScriptTags(html string) []ScriptTag {
	matches := rxScriptBlock.FindAllStringSubmatch(html, -1)
	var tags []ScriptTag
	for _, m := range matches {
		attrs := m[1]
		text := strings.TrimSpace(m[2])
		tags = append(tags, ScriptTag{
			Text: text,
			Src:  extractAttr(attrs, rxScriptSrc),
			Type: extractAttr(attrs, rxScriptType),
		})
	}
	return tags
}

func extractAttr(attrs string, rx *regexp.Regexp) string {
	m := rx.FindStringSubmatch(attrs)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// FindTurnstileLoaderURL finds the URL of the Turnstile loader script
// (api.js) in the page HTML. Returns the default URL if no script tag is
// found.
func FindTurnstileLoaderURL(html, pageURL string) string {
	const defaultLoader = "https://challenges.cloudflare.com/turnstile/v0/api.js"
	tags := ExtractScriptTags(html)
	for _, tag := range tags {
		if tag.Src == "" {
			continue
		}
		if strings.Contains(tag.Src, "challenges.cloudflare.com/turnstile/") ||
			strings.Contains(tag.Src, "/api.js") {
			resolved, err := resolveURL(pageURL, tag.Src)
			if err != nil {
				continue
			}
			return resolved
		}
	}
	return defaultLoader
}

// IframeParams holds the parameters needed to construct the Turnstile iframe URL.
type IframeParams struct {
	// WidgetID is the 5-character random widget ID.
	WidgetID string
	// Sitekey is the Turnstile sitekey.
	Sitekey string
	// Theme is the widget theme (e.g., "auto", "light", "dark").
	Theme string
	// Size is the widget size (e.g., "normal", "compact").
	Size string
	// Language is the language code (e.g., "en", "auto").
	Language string
	// FeedbackEnabled controls whether feedback is enabled (fbE vs fbD).
	FeedbackEnabled bool
}

// BuildIframeURL constructs the Turnstile iframe URL from the loader origin
// and widget parameters. The URL format follows cfsolve's extra_params::iframe_url:
//
//	{origin}/cdn-cgi/challenge-platform/h/{route}/turnstile/f/av0/rch/{widget_id}/{sitekey}/{theme}/{size}/{feedback}/new/{...}?lang={language}
func BuildIframeURL(loaderURL string, route string, params IframeParams) (string, error) {
	parsed, err := url.Parse(loaderURL)
	if err != nil {
		return "", err
	}
	origin := parsed.Scheme + "://" + parsed.Host
	theme := params.Theme
	if theme == "" {
		theme = "auto"
	}
	size := params.Size
	if size == "" {
		size = "normal"
	}
	lang := params.Language
	if lang == "" {
		lang = "en"
	}
	feedback := "fbD"
	if params.FeedbackEnabled {
		feedback = "fbE"
	}
	widgetID := params.WidgetID
	if widgetID == "" {
		widgetID = randomWidgetID()
	}
	path := fmt.Sprintf("/cdn-cgi/challenge-platform/h/%s/turnstile/f/av0/rch/%s/%s/%s/%s/%s/new",
		route, widgetID, params.Sitekey, theme, size, feedback)
	iframeURL := origin + path + "?" + url.Values{"lang": []string{lang}}.Encode()
	return iframeURL, nil
}

// randomWidgetID generates a 5-character random widget ID using the api.js
// format (lowercase letters and digits).
func randomWidgetID() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[b[i]%byte(len(chars))]
	}
	return string(b)
}
