// Package challenge implements the Cloudflare challenge page orchestration:
// parsing the challenge page HTML to extract the orchestrator URL, the
// loading address, and the inline JavaScript; fetching the orchestrator
// script; and building the Turnstile iframe URL from the loader script.
//
// These functions operate on raw HTML and JavaScript text. They do not
// execute JavaScript and do not depend on the challenge-program VM.
package challenge

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ChallengePage holds the parsed state of a Cloudflare challenge page.
type ChallengePage struct {
	// URL is the final URL of the challenge page response.
	URL string
	// HTML is the raw HTML of the challenge page.
	HTML string
	// Inline is the inline JavaScript extracted from the page (the bootstrap
	// script that installs _cf_chl_opt and loads the orchestrator).
	Inline string
	// Orchestrator is the URL of the orchestrator script, extracted from the
	// inline JavaScript.
	Orchestrator string
	// Loading is the temporary page URL used while the orchestrator loads.
	// Contains __cf_chl_rt_tk=.
	Loading string
	// Answered is the page address to restore after the challenge, extracted
	// from the cUPMDTk option. May be empty.
	Answered string
	// CfChlOpt is the _cf_chl_opt object's key-value pairs extracted from the
	// inline script.
	CfChlOpt map[string]string
}

var (
	// Matches the orchestrator path: starts with /cdn-cgi/challenge-platform/
	// and contains /orchestrate/.
	rxOrchestratorPath = regexp.MustCompile(`['"](/cdn-cgi/challenge-platform/[^'"]*/orchestrate/[^'"]*)['"]`)
	// Matches the loading address: contains __cf_chl_rt_tk=.
	rxLoadingAddress = regexp.MustCompile(`['"]([^'"]*__cf_chl_rt_tk=[^'"]*)['"]`)
	// Matches _cf_chl_opt assignment: window._cf_chl_opt = {...}
	rxCfChlOpt = regexp.MustCompile(`(?s)window\._cf_chl_opt\s*=\s*\{([^}]*)\}`)
	// Matches key-value pairs inside _cf_chl_opt: key: 'value' or key: "value"
	rxCfChlOptPair = regexp.MustCompile(`(\w+)\s*:\s*['"]([^'"]*)['"]`)
	// Matches cUPMDTk specifically.
	rxCUPMDTk = regexp.MustCompile(`cUPMDTk\s*:\s*['"]([^'"]*)['"]`)
)

// ParseChallengePage parses the HTML of a Cloudflare challenge page and
// extracts the orchestrator URL, loading address, and inline JavaScript.
// Returns nil if the HTML is not a challenge page.
func ParseChallengePage(html, pageURL string) (*ChallengePage, error) {
	inline := ExtractInlineJavaScript(html)
	if inline == "" || !strings.Contains(inline, "_cf_chl_opt") {
		return nil, nil
	}

	cp := &ChallengePage{
		URL:    pageURL,
		HTML:   html,
		Inline: inline,
	}

	// Extract the orchestrator path.
	if m := rxOrchestratorPath.FindStringSubmatch(inline); len(m) >= 2 {
		orchestrator, err := resolveURL(pageURL, m[1])
		if err != nil {
			return nil, fmt.Errorf("resolving orchestrator URL: %w", err)
		}
		cp.Orchestrator = orchestrator
	}

	// Extract the loading address.
	if m := rxLoadingAddress.FindStringSubmatch(inline); len(m) >= 2 {
		loading, err := resolveURL(pageURL, m[1])
		if err != nil {
			return nil, fmt.Errorf("resolving loading URL: %w", err)
		}
		cp.Loading = loading
	}

	// Extract the cUPMDTk (answered) address.
	if m := rxCUPMDTk.FindStringSubmatch(inline); len(m) >= 2 {
		answered, err := resolveURL(pageURL, m[1])
		if err == nil {
			cp.Answered = answered
		}
	}

	// Extract _cf_chl_opt key-value pairs.
	cp.CfChlOpt = extractCfChlOpt(inline)

	return cp, nil
}

// extractCfChlOpt extracts the _cf_chl_opt object's string key-value pairs.
func extractCfChlOpt(inline string) map[string]string {
	result := make(map[string]string)
	matches := rxCfChlOpt.FindStringSubmatch(inline)
	if len(matches) < 2 {
		return result
	}
	body := matches[1]
	for _, pair := range rxCfChlOptPair.FindAllStringSubmatch(body, -1) {
		if len(pair) >= 3 {
			result[pair[1]] = pair[2]
		}
	}
	return result
}

// resolveURL resolves a possibly-relative URL against a base URL.
func resolveURL(base, ref string) (string, error) {
	if base == "" {
		return ref, nil
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	refURL, err := baseURL.Parse(ref)
	if err != nil {
		return "", err
	}
	return refURL.String(), nil
}
