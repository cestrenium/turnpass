package solver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cestrenium/turnpass/internal/challenge"
	tperr "github.com/cestrenium/turnpass/internal/errors"
	"github.com/cestrenium/turnpass/internal/transport"
)

// OrchestrationResult holds the results of the HTTP orchestration phase:
// all the resources fetched and parsed before the challenge-program VM
// would run.
type OrchestrationResult struct {
	// PageURL is the final URL of the fetched page.
	PageURL string
	// PageHTML is the raw HTML of the fetched page.
	PageHTML string
	// PageStatus is the HTTP status of the page response.
	PageStatus int

	// ChallengePage is the parsed challenge page, or nil if the page is not
	// a Cloudflare challenge page.
	ChallengePage *challenge.ChallengePage

	// OrchestratorScript is the fetched orchestrator script source (for
	// challenge pages only).
	OrchestratorScript string

	// LoaderURL is the URL of the Turnstile loader script (api.js).
	LoaderURL string
	// LoaderScript is the fetched loader script source.
	LoaderScript string
	// LoaderInfo is the parsed loader info (build hash, route).
	LoaderInfo *challenge.LoaderInfo

	// IframeURL is the constructed Turnstile iframe URL.
	IframeURL string
	// IframeHTML is the fetched iframe HTML.
	IframeHTML string
	// IframeJS is the inline JavaScript extracted from the iframe.
	IframeJS string

	// Widget is the Turnstile widget being solved.
	Widget *Widget
}

// orchestrate performs the HTTP-level challenge orchestration: fetching the
// page, detecting the challenge type, fetching the orchestrator script (for
// challenge pages) or the loader script (for widget pages), building and
// fetching the iframe, and extracting inline JavaScript.
//
// This is everything that happens before the challenge-program VM runs. The
// VM execution (deobfuscation, payload construction, POST interaction) is the
// remaining piece that returns Unsupported.
func (s *Solver) orchestrate(ctx context.Context, client *transport.BrowserClient, pageURL string, pageHTML string, pageStatus int, widget *Widget, sink Sink) (*OrchestrationResult, error) {
	result := &OrchestrationResult{
		PageURL:    pageURL,
		PageHTML:   pageHTML,
		PageStatus: pageStatus,
		Widget:     widget,
	}

	// Try to parse as a challenge page.
	cp, err := challenge.ParseChallengePage(pageHTML, pageURL)
	if err != nil {
		return nil, tperr.NewUnsupported(fmt.Errorf("parsing challenge page: %w", err))
	}
	result.ChallengePage = cp

	if cp != nil {
		// This is a Cloudflare challenge page. Fetch the orchestrator script.
		// For challenge pages, the orchestrator renders the Turnstile widget;
		// the iframe URL comes from the orchestrator's first response, not
		// from the loader script. We fetch the orchestrator and loader here,
		// but do not attempt to build/fetch the iframe (that requires the VM).
		sink.Progress(fmt.Sprintf("challenge page detected; orchestrator: %s", cp.Orchestrator))
		if cp.Orchestrator != "" {
			sink.Progress("fetching orchestrator script")
			script, err := fetchScript(ctx, client, "orchestrator", cp.Orchestrator, pageURL)
			if err != nil {
				return nil, tperr.NewNetwork(fmt.Errorf("fetching orchestrator: %w", err))
			}
			result.OrchestratorScript = script
			sink.Progress(fmt.Sprintf("orchestrator script: %d bytes", len(script)))
		}
		// Also fetch the loader script for completeness (the orchestrator
		// may reload it).
		loaderURL := challenge.FindTurnstileLoaderURL(pageHTML, pageURL)
		result.LoaderURL = loaderURL
		sink.Progress(fmt.Sprintf("loader script URL: %s", loaderURL))
		sink.Progress("fetching loader script (api.js)")
		loaderScript, err := fetchScript(ctx, client, "script", loaderURL, pageURL)
		if err != nil {
			sink.Progress(fmt.Sprintf("warning: could not fetch loader script: %v", err))
		} else {
			result.LoaderScript = loaderScript
			sink.Progress(fmt.Sprintf("loader script: %d bytes", len(loaderScript)))
			// Try to parse the loader script for build/route.
			if loaderInfo, err := challenge.ParseLoaderScript(loaderScript); err == nil {
				result.LoaderInfo = loaderInfo
				sink.Progress(fmt.Sprintf("loader build=%s route=%s", loaderInfo.Build, loaderInfo.Route))
			} else {
				sink.Progress(fmt.Sprintf("warning: could not parse loader script: %v", err))
			}
		}
		// For challenge pages, the iframe URL comes from the orchestrator's
		// response program, which requires the VM to execute. We do not
		// attempt to build or fetch the iframe here.
		sink.Progress("challenge page orchestration complete; iframe URL requires VM execution")
		return result, nil
	}

	// This is a normal page with a Turnstile widget (not a challenge page).
	// Find the Turnstile loader script URL.
	loaderURL := challenge.FindTurnstileLoaderURL(pageHTML, pageURL)
	result.LoaderURL = loaderURL
	sink.Progress(fmt.Sprintf("loader script URL: %s", loaderURL))

	// Fetch the loader script.
	sink.Progress("fetching loader script (api.js)")
	loaderScript, err := fetchScript(ctx, client, "script", loaderURL, pageURL)
	if err != nil {
		return nil, tperr.NewNetwork(fmt.Errorf("fetching loader script: %w", err))
	}
	result.LoaderScript = loaderScript
	sink.Progress(fmt.Sprintf("loader script: %d bytes", len(loaderScript)))

	// Parse the loader script for build hash and route.
	loaderInfo, err := challenge.ParseLoaderScript(loaderScript)
	if err != nil {
		sink.Progress(fmt.Sprintf("warning: could not parse loader script: %v", err))
		// Use defaults.
		loaderInfo = &challenge.LoaderInfo{Build: "unknown", Route: "b"}
	}
	result.LoaderInfo = loaderInfo
	sink.Progress(fmt.Sprintf("loader build=%s route=%s", loaderInfo.Build, loaderInfo.Route))

	// Build the iframe URL.
	if widget != nil && widget.Sitekey != "" {
		params := challenge.IframeParams{
			Sitekey:  widget.Sitekey,
			Theme:    "auto",
			Size:     "normal",
			Language: "en",
		}
		iframeURL, err := challenge.BuildIframeURL(loaderURL, loaderInfo.Route, params)
		if err != nil {
			return nil, tperr.NewConfig(fmt.Errorf("building iframe URL: %w", err))
		}
		result.IframeURL = iframeURL
		sink.Progress(fmt.Sprintf("iframe URL: %s", iframeURL))

		// Fetch the iframe HTML.
		sink.Progress("fetching iframe")
		iframeHTML, err := fetchHTML(ctx, client, "iframe", iframeURL, pageURL)
		if err != nil {
			sink.Progress(fmt.Sprintf("warning: could not fetch iframe: %v", err))
		} else {
			result.IframeHTML = iframeHTML
			sink.Progress(fmt.Sprintf("iframe HTML: %d bytes", len(iframeHTML)))

			// Extract inline JavaScript from the iframe.
			iframeJS := challenge.ExtractInlineJavaScript(iframeHTML)
			result.IframeJS = iframeJS
			if iframeJS != "" {
				sink.Progress(fmt.Sprintf("iframe inline JS: %d bytes", len(iframeJS)))
			} else {
				sink.Progress("warning: no inline JavaScript found in iframe")
			}
		}
	}

	return result, nil
}

// fetchScript fetches a script resource using the given request kind.
func fetchScript(ctx context.Context, client *transport.BrowserClient, kind, scriptURL, pageURL string) (string, error) {
	resp, err := client.Get(ctx, kind, scriptURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status %d for %s", resp.StatusCode, scriptURL)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// fetchHTML fetches an HTML resource using the given request kind.
func fetchHTML(ctx context.Context, client *transport.BrowserClient, kind, htmlURL, referrerURL string) (string, error) {
	resp, err := client.Get(ctx, kind, htmlURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status %d for %s", resp.StatusCode, htmlURL)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// fetchOrchestrator fetches the orchestrator script from a challenge page.
func fetchOrchestrator(ctx context.Context, client *transport.BrowserClient, orchestratorURL, loadingURL string) (string, error) {
	// The orchestrator is fetched with the loading URL as referrer.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, orchestratorURL, nil)
	if err != nil {
		return "", err
	}
	// Apply the client's default headers.
	resp, err := client.Do(ctx, "orchestrator", http.MethodGet, orchestratorURL, nil, map[string]string{
		"Referer": loadingURL,
	})
	_ = req
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status %d for orchestrator", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// resolveReferer returns the referrer for a request from pageURL to targetURL.
func resolveReferer(pageURL, targetURL string) string {
	if pageURL == "" {
		return ""
	}
	parsed, err := url.Parse(pageURL)
	if err != nil {
		return pageURL
	}
	// WebKit sends only the origin as referrer for cross-origin requests.
	return parsed.Scheme + "://" + parsed.Host + "/"
}

// postChallengePayload posts an encoded challenge body to the challenge POST URL.
// This is used by the VM execution phase (not yet implemented).
func postChallengePayload(ctx context.Context, client *transport.BrowserClient, iframeURL, postURL, cfChl, body string) (*http.Response, error) {
	return client.Post(ctx, "challenge_post", postURL, "text/plain;charset=UTF-8", strings.NewReader(body))
}
