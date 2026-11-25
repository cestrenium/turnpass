// Command turnpass-x is the FlareSolverr-compatible API server.
//
// Usage:
//
//	turnpass-x --profile profiles/safari-26-ios.json --host 0.0.0.0 --port 8191
//
// All flags use pflag v1.1.0 with consistent long and short names.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/cestrenium/turnpass/api/handlers"
	"github.com/cestrenium/turnpass/api/server"
	"github.com/cestrenium/turnpass/api/sessions"
	"github.com/cestrenium/turnpass/internal/browserprofile"
	"github.com/cestrenium/turnpass/internal/solver"
)

const version = "0.1.0-dev"

func main() {
	fs := pflag.NewFlagSet("turnpass-x", pflag.ExitOnError)
	host := fs.StringP("host", "H", "0.0.0.0", "Listening address")
	port := fs.IntP("port", "p", 8191, "Listening port")
	profileFlag := fs.StringP("profile", "f", "", "Browser profile JSON file (required)")
	proxyFlag := fs.StringP("proxy", "x", "", "Default proxy URL for all solves")
	timeout := fs.DurationP("timeout", "t", 60*time.Second, "Per-request timeout")
	readTimeout := fs.DurationP("read-timeout", "", 10*time.Second, "HTTP read timeout")
	writeTimeout := fs.DurationP("write-timeout", "", 60*time.Second, "HTTP write timeout")
	requestTimeout := fs.DurationP("request-timeout", "", 5*time.Minute, "Whole-request timeout")
	sessionTTL := fs.DurationP("session-ttl", "", 15*time.Minute, "Default session TTL")
	logLevel := fs.StringP("log-level", "l", "info", "Log level: debug | info | warn | error")
	showVersion := fs.BoolP("version", "V", false, "Print version and exit")

	fs.SetInterspersed(true)
	fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("turnpass-x %s\n", version)
		return
	}

	if *profileFlag == "" {
		fmt.Fprintln(os.Stderr, "turnpass-x: --profile is required")
		fmt.Fprintln(os.Stderr)
		fs.Usage()
		os.Exit(2)
	}

	switch *logLevel {
	case "debug", "info", "warn", "error":
	default:
		fmt.Fprintf(os.Stderr, "turnpass-x: invalid log-level %q\n", *logLevel)
		os.Exit(2)
	}

	b, err := browserprofile.Read(*profileFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "turnpass-x: load profile: %v\n", err)
		os.Exit(1)
	}

	store := sessions.New(*sessionTTL)
	s := solver.New(b)
	dispatcher := handlers.NewDispatcher(store, s, version, *timeout)
	addr := fmt.Sprintf("%s:%d", *host, *port)
	cfg := server.Config{
		Addr:              addr,
		ReadTimeout:       *readTimeout,
		WriteTimeout:      *writeTimeout,
		RequestTimeout:    *requestTimeout,
		SessionDefaultTTL: *sessionTTL,
		Version:           version,
	}
	srv := server.New(cfg, dispatcher, store)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := srv.ListenAndServe(ctx); err != nil {
		log.Fatalf("server: %v", err)
	}
	_ = proxyFlag
}
