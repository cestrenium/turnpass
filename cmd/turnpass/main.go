// Command turnpass is the core solver CLI.
//
// Usage:
//
//	turnpass --url https://example.com/login --profile profiles/safari-26-ios.json --mode auto
//	turnpass --url https://example.com/login --profile p.json --mode turnstile --sitekey 0xABC
//	turnpass --url https://example.com/login --profile p.json --mode challenge
//
// All flags use pflag v1.1.0 with consistent long and short names.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/cestrenium/turnpass/internal/browserprofile"
	tperr "github.com/cestrenium/turnpass/internal/errors"
	"github.com/cestrenium/turnpass/internal/solver"
)

const (
	exitOK          = 0
	exitConfig      = 1
	exitNetwork     = 2
	exitUnsupported = 3
	exitBlocked     = 4
	exitGeneric     = 5
)

func main() {
	fs := pflag.NewFlagSet("turnpass", pflag.ExitOnError)

	urlFlag := fs.StringP("url", "u", "", "Target page URL (required)")
	profileFlag := fs.StringP("profile", "f", "", "Browser profile JSON file (required)")
	modeFlag := fs.StringP("mode", "m", "auto", "Solve mode: auto | turnstile | challenge")
	sitekeyFlag := fs.StringP("sitekey", "k", "", "Turnstile sitekey (selects one widget when multiple exist)")
	actionFlag := fs.StringP("action", "a", "", "Turnstile action (requires --sitekey)")
	cdataFlag := fs.StringP("cdata", "d", "", "Turnstile cData (requires --sitekey)")
	blankPage := fs.BoolP("blank-page", "B", false, "Render the widget on a blank page at --url (requires --sitekey)")
	htmlFile := fs.StringP("html", "H", "", "Read page HTML from this file instead of navigating")
	proxyFlag := fs.StringP("proxy", "p", "", "Proxy URL (http://, https://, socks5://, socks5h://)")
	timeoutFlag := fs.DurationP("timeout", "t", 60*time.Second, "Request timeout")
	trustedRootFlag := fs.StringP("trusted-root", "C", "", "PEM certificate file to trust instead of system roots")
	verbose := fs.BoolP("verbose", "v", false, "Enable verbose progress output on stderr")
	debugDir := fs.StringP("debug-dir", "D", "", "Directory to write debugging artifacts to")

	fs.Lookup("help").Hidden = false
	fs.SetInterspersed(true)
	fs.Parse(os.Args[1:])

	if *urlFlag == "" || *profileFlag == "" {
		fmt.Fprintln(os.Stderr, "turnpass: --url and --profile are required")
		fmt.Fprintln(os.Stderr)
		fs.Usage()
		os.Exit(exitConfig)
	}

	b, err := browserprofile.Read(*profileFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "turnpass: load profile: %v\n", err)
		os.Exit(exitConfig)
	}

	var sink solver.Sink = solver.DiscardSink{}
	if *verbose || *debugDir != "" {
		sink = newVerboseSink(os.Stderr, *debugDir)
	}

	opts := solver.Options{Proxy: *proxyFlag, Timeout: *timeoutFlag, Sink: sink}
	if *trustedRootFlag != "" {
		pem, err := os.ReadFile(*trustedRootFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "turnpass: read trusted-root: %v\n", err)
			os.Exit(exitConfig)
		}
		opts.TrustedRoot = pem
	}

	s := solver.New(b)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	mode := *modeFlag
	if *blankPage {
		mode = "turnstile"
	}

	switch mode {
	case "turnstile":
		req := solver.Turnstile{URL: *urlFlag}
		if *blankPage {
			req.Page = solver.PageBlank
		} else if *htmlFile != "" {
			html, err := os.ReadFile(*htmlFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "turnpass: read html: %v\n", err)
				os.Exit(exitConfig)
			}
			req.Page = solver.PageHTML
			req.HTML = string(html)
		} else {
			req.Page = solver.PageNavigate
		}
		if *sitekeyFlag != "" {
			req.Widget = &solver.Widget{Sitekey: *sitekeyFlag, Action: *actionFlag, CData: *cdataFlag}
		}
		tok, err := s.SolveTurnstile(ctx, req, opts)
		if err != nil {
			exitWithError(err)
			return
		}
		fmt.Println(tok)
	case "challenge":
		cl, err := s.Clear(ctx, *urlFlag, opts)
		if err != nil {
			exitWithError(err)
			return
		}
		fmt.Printf("cf_clearance=%s\n", cl.Clearance)
		for _, c := range cl.Cookies {
			fmt.Println(c)
		}
	case "auto":
		out, err := s.Solve(ctx, *urlFlag, opts)
		if err != nil {
			exitWithError(err)
			return
		}
		switch out.Kind {
		case solver.OutcomeToken:
			fmt.Println(out.Token)
		case solver.OutcomeCleared:
			fmt.Printf("cf_clearance=%s\n", out.Clearance.Clearance)
		}
	default:
		fmt.Fprintf(os.Stderr, "turnpass: unknown mode %q (want auto|turnstile|challenge)\n", mode)
		os.Exit(exitConfig)
	}
}

func exitWithError(err error) {
	var e *tperr.Error
	if !errorAs(err, &e) {
		fmt.Fprintf(os.Stderr, "turnpass: %v\n", err)
		os.Exit(exitGeneric)
	}
	fmt.Fprintf(os.Stderr, "turnpass: [%s] %v\n", e.Category, err)
	switch e.Category {
	case tperr.CategoryConfig, tperr.CategoryNotChallenged:
		os.Exit(exitConfig)
	case tperr.CategoryNetwork, tperr.CategoryChallenged, tperr.CategoryRejected:
		os.Exit(exitNetwork)
	case tperr.CategoryBlocked:
		os.Exit(exitBlocked)
	case tperr.CategoryUnsupported, tperr.CategorySink:
		os.Exit(exitUnsupported)
	default:
		os.Exit(exitGeneric)
	}
}

func errorAs(err error, target any) bool { return errorsAs(err, target) }
