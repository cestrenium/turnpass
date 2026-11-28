// Package solver provides the unified solver interface for Cloudflare
// Turnstile widgets and challenge pages.
//
// A Solver is constructed once per browser profile and shared across solves.
// Each solve gets its own transport, cookie jar and proxy. Solves can run
// concurrently.
//
// The Outcome is a typed sum: either a Turnstile token was acquired, or a
// Cloudflare challenge was cleared and a cf_clearance cookie is available.
package solver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/cestrenium/turnpass/internal/browserprofile"
	"github.com/cestrenium/turnpass/internal/codec"
	tperr "github.com/cestrenium/turnpass/internal/errors"
	"github.com/cestrenium/turnpass/internal/extraparams"
	"github.com/cestrenium/turnpass/internal/payload"
	"github.com/cestrenium/turnpass/internal/protocol"
	"github.com/cestrenium/turnpass/internal/transport"
	"github.com/cestrenium/turnpass/internal/vmexec"
)

// OutcomeKind is the kind of result a solve produced.
type OutcomeKind int

const (
	// OutcomeToken means a Turnstile token was acquired.
	OutcomeToken OutcomeKind = iota
	// OutcomeCleared means a Cloudflare challenge was cleared.
	OutcomeCleared
)

// Outcome is the result of a unified Solve call.
type Outcome struct {
	Kind      OutcomeKind
	Token     string    // set when Kind == OutcomeToken
	Clearance Clearance // set when Kind == OutcomeCleared
}

// Clearance holds the result of clearing a Cloudflare challenge.
type Clearance struct {
	Clearance string   // the cf_clearance cookie value
	Cookies   []string // "name=value" strings for all cookies for the page
	Page      *FetchedPage
}

// PageSource tells the solver where the page's HTML comes from.
type PageSource int

const (
	// PageNavigate fetches the page. A challenge page in its place fails the
	// solve with Challenged.
	PageNavigate PageSource = iota
	// PageHTML uses caller-supplied HTML.
	PageHTML
	// PageBlank renders the named widget on a blank page at the supplied URL.
	PageBlank
)

// Widget specifies which Turnstile widget to solve.
type Widget struct {
	Sitekey string
	Action  string
	CData   string
}

// Turnstile is a Turnstile solve request.
type Turnstile struct {
	URL    string
	Page   PageSource
	HTML   string // used when Page == PageHTML
	Widget *Widget
}

// FetchedPage is a challenge page fetched by the caller.
type FetchedPage struct {
	URL            string
	Status         int
	HTML           string
	ReferrerPolicy string
	SetCookies     []string
}

// Options configures one solve.
type Options struct {
	Proxy       string
	TrustedRoot []byte
	Timeout     time.Duration
	Sink        Sink
}

// Sink receives progress messages and artifacts during a solve.
type Sink interface {
	Progress(msg string)
	Artifact(name string, data []byte) error
}

// DiscardSink ignores everything.
type DiscardSink struct{}

func (DiscardSink) Progress(string)               {}
func (DiscardSink) Artifact(string, []byte) error { return nil }

// Solver solves Turnstile widgets and clears Cloudflare challenge pages.
type Solver struct {
	browser *browserprofile.Browser
}

// New returns a Solver backed by the given browser profile.
func New(b *browserprofile.Browser) *Solver { return &Solver{browser: b} }

// SolveTurnstile solves the specified widget and returns the token.
func (s *Solver) SolveTurnstile(ctx context.Context, req Turnstile, opts Options) (string, error) {
	if req.URL == "" {
		return "", tperr.NewConfig(fmt.Errorf("url is required"))
	}
	if req.Page == PageBlank && req.Widget == nil {
		return "", tperr.NewConfig(fmt.Errorf("a blank page renders no widget of its own; name one to render"))
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		return "", tperr.NewConfig(fmt.Errorf("invalid url: %w", err))
	}

	client, err := s.buildClient(opts)
	if err != nil {
		return "", err
	}

	sink := opts.Sink
	if sink == nil {
		sink = DiscardSink{}
	}
	sink.Progress(fmt.Sprintf("solving turnstile for %s", u))

	var page *protocol.Page
	switch req.Page {
	case PageNavigate:
		page, err = s.navigate(ctx, client, u, sink)
		if err != nil {
			return "", err
		}
		if page.Challenge != protocol.ChallengeNone && page.Challenge != protocol.ChallengeTurnstile {
			return "", tperr.NewChallenged(page.Status)
		}
	case PageHTML:
		page = protocol.ParseHTMLBytes([]byte(req.HTML), 200, req.URL)
	case PageBlank:
		page = protocol.ParseHTMLBytes([]byte(blankPageHTML), 200, req.URL)
	}

	widget := req.Widget
	if widget == nil {
		if len(page.Widgets) == 0 {
			return "", tperr.NewUnsupported(fmt.Errorf("no turnstile widget found on the page"))
		}
		found := page.Widgets[0]
		widget = &Widget{Sitekey: found.Sitekey, Action: found.Action, CData: found.CData}
	}

	sink.Progress(fmt.Sprintf("widget sitekey=%s action=%q cdata=%q", widget.Sitekey, widget.Action, widget.CData))

	// Perform the HTTP orchestration: fetch the loader script, build and
	// fetch the iframe, extract inline JavaScript. This is everything before
	// the challenge-program VM runs.
	orchResult, err := s.orchestrate(ctx, client, req.URL, page.HTML, page.Status, widget, sink)
	if err != nil {
		return "", err
	}

	// Save orchestration artifacts for debugging.
	if orchResult.IframeJS != "" {
		sink.Artifact("iframe.js", []byte(orchResult.IframeJS))
	}
	if orchResult.LoaderScript != "" {
		sink.Artifact("loader.js", []byte(orchResult.LoaderScript))
	}
	if orchResult.OrchestratorScript != "" {
		sink.Artifact("orchestrator.js", []byte(orchResult.OrchestratorScript))
	}

	// Attempt to build and send the first payload if we have all the pieces.
	if orchResult.InitialRequest != nil && orchResult.EncoderParams != nil &&
		s.browser.ParsedAnswers != nil {
		sink.Progress("attempting first payload construction and POST")

		// Build the first payload from answers and extraParams.
		var ep *extraparams.ExtraParams
		if orchResult.ExtraParams != nil {
			ep = orchResult.ExtraParams
		}
		options := make(map[string]interface{})
		if orchResult.InitialRequest != nil {
			options["cf_chl"] = orchResult.InitialRequest.CfChl
			options["ray"] = orchResult.InitialRequest.Ray
		}

		p, err := payload.BuildFirstPayload(s.browser.ParsedAnswers, ep, options)
		if err != nil {
			sink.Progress(fmt.Sprintf("warning: could not build first payload: %v", err))
		} else {
			sink.Progress(fmt.Sprintf("first payload: %d fields", p.Len()))

			// Encode the payload using the codec.
			codec, err := codec.NewCodec(
				orchResult.EncoderParams.Alphabet,
				orchResult.EncoderParams.Modulus,
				orchResult.EncoderParams.Secret,
			)
			if err != nil {
				sink.Progress(fmt.Sprintf("warning: could not create codec: %v", err))
			} else {
				payloadJSON, _ := p.MarshalJSON()
				encoded, err := codec.Encode(payloadJSON)
				if err != nil {
					sink.Progress(fmt.Sprintf("warning: could not encode payload: %v", err))
				} else {
					sink.Progress(fmt.Sprintf("encoded payload: %d chars", len(encoded)))

					// POST the payload to the challenge URL.
					postResult, err := PostChallenge(ctx, client, orchResult.InitialRequest,
						orchResult.IframeURL, encoded, StageInitial, sink)
					if err != nil {
						sink.Progress(fmt.Sprintf("warning: POST failed: %v", err))
					} else {
						sink.Progress(fmt.Sprintf("POST result: status=%d, program=%d bytes",
							postResult.Status, len(postResult.Program)))
						if len(postResult.Program) > 0 {
							sink.Artifact("first-response-program.bin", postResult.Program)
						}
					}
				}
			}
		}
	}

	// The challenge-program VM cannot yet execute real challenge programs
	// because the orchestrator/iframe JS requires full deobfuscation to
	// extract the VM class, encoding constants, and initial program.
	return "", tperr.NewUnsupported(fmt.Errorf(
		"challenge VM execution requires fully deobfuscated JS; " +
			"HTTP orchestration, deobfuscation, codec, payload, and POST " +
			"infrastructure are complete; the remaining gap is extracting " +
			"the VM class and encoding constants from deobfuscated JS; " +
			"see KNOWN_LIMITATIONS.md on the docs branch"))
}

// Clear navigates to the page and clears the Cloudflare challenge.
func (s *Solver) Clear(ctx context.Context, pageURL string, opts Options) (Clearance, error) {
	return s.clearFrom(ctx, pageURL, opts, nil)
}

// ClearFetched clears a challenge page already fetched by the caller.
func (s *Solver) ClearFetched(ctx context.Context, page FetchedPage, opts Options) (Clearance, error) {
	return s.clearFrom(ctx, page.URL, opts, &page)
}

func (s *Solver) clearFrom(ctx context.Context, pageURL string, opts Options, fetched *FetchedPage) (Clearance, error) {
	if pageURL == "" {
		return Clearance{}, tperr.NewConfig(fmt.Errorf("url is required"))
	}
	u, err := url.Parse(pageURL)
	if err != nil {
		return Clearance{}, tperr.NewConfig(fmt.Errorf("invalid url: %w", err))
	}
	client, err := s.buildClient(opts)
	if err != nil {
		return Clearance{}, err
	}
	sink := opts.Sink
	if sink == nil {
		sink = DiscardSink{}
	}

	var page *protocol.Page
	if fetched != nil {
		page = protocol.ParseHTMLBytes([]byte(fetched.HTML), fetched.Status, fetched.URL)
		for _, sc := range fetched.SetCookies {
			client.AddCookie(u, sc)
		}
	} else {
		page, err = s.navigate(ctx, client, u, sink)
		if err != nil {
			return Clearance{}, err
		}
	}

	if page.Challenge == protocol.ChallengeNone {
		return Clearance{}, tperr.NewNotChallenged()
	}

	sink.Progress(fmt.Sprintf("detected %s challenge at %s (status %d)", page.Challenge, u, page.Status))

	// Perform the HTTP orchestration: parse the challenge page, fetch the
	// orchestrator script, fetch the loader, build and fetch the iframe.
	orchResult, err := s.orchestrate(ctx, client, pageURL, page.HTML, page.Status, nil, sink)
	if err != nil {
		return Clearance{}, err
	}

	// Save orchestration artifacts for debugging.
	if orchResult.OrchestratorScript != "" {
		sink.Artifact("orchestrator.js", []byte(orchResult.OrchestratorScript))
	}
	if orchResult.IframeJS != "" {
		sink.Artifact("iframe.js", []byte(orchResult.IframeJS))
	}
	if orchResult.LoaderScript != "" {
		sink.Artifact("loader.js", []byte(orchResult.LoaderScript))
	}

	// Attempt orchestrator POST if we have all required pieces.
	if orchResult.InitialRequest != nil && orchResult.EncoderParams != nil {
		sink.Progress("attempting orchestrator POST")

		// Try the goja-based encoder first (produces correct payload
		// structure with the real VM-computed key transform).
		if orchResult.EncoderParams.RunnerName != "" && orchResult.EncoderParams.InitialProgram != "" && orchResult.EncoderParams.Encoder != "" {
			sink.Progress("attempting goja-based payload encoding")
			encResult, err := vmexec.EncodePayload(
				orchResult.OrchestratorScript,
				orchResult.EncoderParams.RunnerName,
				orchResult.EncoderParams.InitialProgram,
				orchResult.EncoderParams.Encoder,
				orchResult.InitialRequest.Options,
			)
			if err != nil {
				sink.Progress(fmt.Sprintf("warning: goja encoding failed: %v", err))
			} else if encResult == nil {
				sink.Progress("warning: goja encoding returned nil result")
			} else {
				// If the secret was captured, update the encoder params
				// so the codec fallback uses the correct secret.
				if encResult.SecretFound {
					sink.Progress(fmt.Sprintf("captured secret: %x (%q)", encResult.Secret, string(encResult.Secret[:])))
					orchResult.EncoderParams.Secret = encResult.Secret
				}

				if encResult.EncodedPayload != "" {
					sink.Progress(fmt.Sprintf("goja-encoded payload: %d chars", len(encResult.EncodedPayload)))

					// POST the goja-encoded payload.
					postResult, err := PostChallenge(ctx, client, orchResult.InitialRequest,
						orchResult.PageURL, encResult.EncodedPayload, StageOrchestrator, sink)
					if err != nil {
						sink.Progress(fmt.Sprintf("warning: orchestrator POST failed: %v", err))
					} else {
						sink.Progress(fmt.Sprintf("orchestrator POST result: status=%d, program=%d bytes",
							postResult.Status, len(postResult.Program)))
						if len(postResult.Program) > 0 {
							sink.Artifact("orchestrator-response-program.bin", postResult.Program)
						}
						if postResult.Status == 200 {
							sink.Progress("orchestrator POST succeeded with HTTP 200!")
						}
					}
				} else {
					encDebug := ""
					if encResult.EncoderCallResult != "" {
						encDebug = fmt.Sprintf(", encoderCall=%s", truncateStr(encResult.EncoderCallResult, 200))
					}
					sink.Progress(fmt.Sprintf("warning: goja encoding produced empty payload (keyTransform=%q, error=%v%s)",
						encResult.KeyTransformFunction, encResult.Error, encDebug))
				}
			}
		}

		// Fall back to the codec-based encoding if goja encoding didn't produce a payload.
		cfChlOpt := orchResult.InitialRequest.Options
		options := make(map[string]interface{})
		for k, v := range cfChlOpt {
			options[k] = v
		}
		options["frame_top"] = false
		options["frame_self"] = false

		// Create the codec.
		codec, err := codec.NewCodec(
			orchResult.EncoderParams.Alphabet,
			orchResult.EncoderParams.Modulus,
			orchResult.EncoderParams.Secret,
		)
		if err != nil {
			sink.Progress(fmt.Sprintf("warning: could not create codec: %v", err))
		} else {
			// Build a minimal payload JSON.
			payloadJSON, _ := json.Marshal(options)
			sink.Progress(fmt.Sprintf("payload: %d bytes", len(payloadJSON)))

			// Encode the payload.
			encoded, err := codec.Encode(payloadJSON)
			if err != nil {
				sink.Progress(fmt.Sprintf("warning: could not encode payload: %v", err))
			} else {
				sink.Progress(fmt.Sprintf("encoded payload: %d chars", len(encoded)))

				// POST to the orchestrator URL.
				postResult, err := PostChallenge(ctx, client, orchResult.InitialRequest,
					orchResult.PageURL, encoded, StageOrchestrator, sink)
				if err != nil {
					sink.Progress(fmt.Sprintf("warning: orchestrator POST failed: %v", err))
				} else {
					sink.Progress(fmt.Sprintf("orchestrator POST result: status=%d, program=%d bytes",
						postResult.Status, len(postResult.Program)))
					if len(postResult.Program) > 0 {
						sink.Artifact("orchestrator-response-program.bin", postResult.Program)
					}
					if postResult.Status == 200 {
						sink.Progress("orchestrator POST succeeded with HTTP 200")
					}
				}
			}
		}
	}

	// The orchestrator's response contains a VM program that renders the
	// Turnstile widget. Executing this program requires the full VM
	// (handler execution, register masking, path exploration) which is
	// the largest remaining piece.
	_ = page
	return Clearance{}, tperr.NewUnsupported(fmt.Errorf(
		"orchestrator POST attempted; VM execution of response program " +
			"is the remaining piece (requires handler execution, register " +
			"masking, path exploration); see KNOWN_LIMITATIONS.md"))
}

// Solve navigates to the page, then clears a challenge or solves the page's
// first Turnstile widget.
func (s *Solver) Solve(ctx context.Context, pageURL string, opts Options) (Outcome, error) {
	if pageURL == "" {
		return Outcome{}, tperr.NewConfig(fmt.Errorf("url is required"))
	}
	u, err := url.Parse(pageURL)
	if err != nil {
		return Outcome{}, tperr.NewConfig(fmt.Errorf("invalid url: %w", err))
	}
	client, err := s.buildClient(opts)
	if err != nil {
		return Outcome{}, err
	}
	sink := opts.Sink
	if sink == nil {
		sink = DiscardSink{}
	}
	page, err := s.navigate(ctx, client, u, sink)
	if err != nil {
		return Outcome{}, err
	}
	switch page.Challenge {
	case protocol.ChallengeNone:
		return Outcome{}, tperr.NewNotChallenged()
	case protocol.ChallengeTurnstile:
		if len(page.Widgets) == 0 {
			return Outcome{}, tperr.NewUnsupported(fmt.Errorf("page has no turnstile widget"))
		}
		w := page.Widgets[0]
		tok, err := s.SolveTurnstile(ctx, Turnstile{URL: pageURL, Page: PageHTML, HTML: page.HTML, Widget: &Widget{Sitekey: w.Sitekey, Action: w.Action, CData: w.CData}}, opts)
		if err != nil {
			return Outcome{}, err
		}
		return Outcome{Kind: OutcomeToken, Token: tok}, nil
	default:
		cl, err := s.Clear(ctx, pageURL, opts)
		if err != nil {
			return Outcome{}, err
		}
		return Outcome{Kind: OutcomeCleared, Clearance: cl}, nil
	}
}

func (s *Solver) buildClient(opts Options) (*transport.BrowserClient, error) {
	cfg := transport.Config{
		Fingerprint: s.browser.Fingerprint,
		Proxy:       opts.Proxy,
		TrustedRoot: opts.TrustedRoot,
		Timeout:     opts.Timeout,
	}
	return transport.New(cfg)
}

func (s *Solver) navigate(ctx context.Context, c *transport.BrowserClient, u *url.URL, sink Sink) (*protocol.Page, error) {
	sink.Progress(fmt.Sprintf("navigating to %s", u))
	resp, err := c.Get(ctx, "navigation", u.String())
	if err != nil {
		return nil, tperr.NewNetwork(err)
	}
	defer resp.Body.Close()
	page, err := protocol.ParsePage(resp, u.String())
	if err != nil {
		return nil, tperr.NewNetwork(err)
	}
	sink.Progress(fmt.Sprintf("got %d (%d bytes)", page.Status, len(page.HTML)))
	return page, nil
}

// PageDocument is a trimmed view of a fetched page, for the API layer.
type PageDocument struct {
	URL     string
	Status  int
	HTML    string
	Headers http.Header
}

// ReadDocument fetches a URL and returns a PageDocument. Used by the API
// layer when it needs to return the final page content.
func ReadDocument(ctx context.Context, c *transport.BrowserClient, kind, rawURL string) (*PageDocument, error) {
	resp, err := c.Get(ctx, kind, rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &PageDocument{URL: rawURL, Status: resp.StatusCode, HTML: string(body), Headers: resp.Header.Clone()}, nil
}

const blankPageHTML = "<!DOCTYPE html><html><head></head><body></body></html>"
