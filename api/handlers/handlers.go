// Package handlers implements the FlareSolverr command dispatch.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cestrenium/turnpass/api/sessions"
	"github.com/cestrenium/turnpass/api/types"
	tperr "github.com/cestrenium/turnpass/internal/errors"
	"github.com/cestrenium/turnpass/internal/solver"
)

// Dispatcher routes FlareSolverr commands to handlers.
type Dispatcher struct {
	Store    *sessions.Store
	Solver   *solver.Solver
	Version  string
	Timeout  time.Duration
}

// NewDispatcher returns a Dispatcher.
func NewDispatcher(store *sessions.Store, s *solver.Solver, version string, timeout time.Duration) *Dispatcher {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &Dispatcher{Store: store, Solver: s, Version: version, Timeout: timeout}
}

// Handle dispatches a request and returns the response.
func (d *Dispatcher) Handle(ctx context.Context, req types.Request) types.Response {
	start := types.Now()
	defer func() {
		// handled below with EndTimestamp
	}()

	var (
		resp types.Response
	)
	switch req.Cmd {
	case "request.get":
		resp = d.handleGet(ctx, req)
	case "request.post":
		resp = d.handlePost(ctx, req)
	case "sessions.create":
		resp = d.handleSessionCreate(req)
	case "sessions.list":
		resp = d.handleSessionList()
	case "sessions.destroy":
		resp = d.handleSessionDestroy(req)
	default:
		resp = types.NewError(fmt.Sprintf("Unknown cmd: %s", req.Cmd), d.Version)
	}
	resp.StartTimestamp = start
	resp.EndTimestamp = types.Now()
	if resp.Version == "" {
		resp.Version = d.Version
	}
	return resp
}

func (d *Dispatcher) handleGet(ctx context.Context, req types.Request) types.Response {
	if req.URL == "" {
		return types.NewError("url is required", d.Version)
	}
	return d.doRequest(ctx, req, "GET", "")
}

func (d *Dispatcher) handlePost(ctx context.Context, req types.Request) types.Response {
	if req.URL == "" {
		return types.NewError("url is required", d.Version)
	}
	return d.doRequest(ctx, req, "POST", req.PostData)
}

func (d *Dispatcher) doRequest(ctx context.Context, req types.Request, method, postData string) types.Response {
	if req.MaxTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.MaxTimeout)*time.Millisecond)
		defer cancel()
	}

	if d.Solver == nil {
		return types.NewError("solver not configured", d.Version)
	}

	// Resolve the session. If a session ID is supplied, reuse it (and its
	// cookies); otherwise solve without a persistent session.
	var sess *sessions.Session
	if req.Session != "" {
		var err error
		sess, err = d.Store.Get(req.Session, true)
		if err != nil {
			return types.NewError(err.Error(), d.Version)
		}
	}

	opts := solver.Options{Timeout: d.Timeout}
	// Use the unified Solve to detect challenge vs ordinary page.
	outcome, err := d.Solver.Solve(ctx, req.URL, opts)
	if err != nil {
		return d.errorResponse(err, req.Session)
	}

	// Build the FlareSolverr solution.
	sol := &types.Solution{
		URL:       req.URL,
		UserAgent: d.SolverBrowserUA(),
	}
	switch outcome.Kind {
	case solver.OutcomeToken:
		sol.Status = 200
		sol.HTML = fmt.Sprintf("<!-- turnstile token: %s -->", outcome.Token)
	case solver.OutcomeCleared:
		sol.Status = 200
		sol.HTML = outcome.Clearance.Page.HTML
		sol.URL = outcome.Clearance.Page.URL
		cookiesOut := make([]types.Cookie, 0, len(outcome.Clearance.Cookies))
		for _, c := range outcome.Clearance.Cookies {
			parts := strings.SplitN(c, "=", 2)
			ck := types.Cookie{Name: parts[0]}
			if len(parts) > 1 {
				ck.Value = parts[1]
			}
			cookiesOut = append(cookiesOut, ck)
		}
		sol.Cookies = cookiesOut
	}
	if sess != nil {
		// Merge the session's existing cookies into the solution.
		existing, _ := d.Store.CookiesForSession(sess.ID)
		sol.Cookies = append(sol.Cookies, existing...)
	}

	resp := types.NewOK("Challenge solved!", d.Version, req.Session, sol)
	if req.ReturnOnlyCookies {
		resp.Solution.HTML = ""
	}
	return resp
}

func (d *Dispatcher) handleSessionCreate(req types.Request) types.Response {
	sess, err := d.Store.Create(req.Session, req.SessionTTLMinutes)
	if err != nil {
		return types.NewError(err.Error(), d.Version)
	}
	return types.NewOK("Session created successfully.", d.Version, sess.ID, nil)
}

func (d *Dispatcher) handleSessionList() types.Response {
	list := d.Store.List()
	ids := make([]string, 0, len(list))
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	b, _ := json.Marshal(ids)
	return types.Response{
		Status:  types.StatusOK,
		Message: "Session list retrieved.",
		Version: d.Version,
		Solution: &types.Solution{HTML: string(b)},
	}
}

func (d *Dispatcher) handleSessionDestroy(req types.Request) types.Response {
	if req.Session == "" {
		return types.NewError("session is required", d.Version)
	}
	if err := d.Store.Destroy(req.Session); err != nil {
		return types.NewError(err.Error(), d.Version)
	}
	return types.NewOK("Session destroyed successfully.", d.Version, req.Session, nil)
}

func (d *Dispatcher) errorResponse(err error, sessionID string) types.Response {
	var e *tperr.Error
	if errorAs(err, &e) {
		switch e.Category {
		case tperr.CategoryNotChallenged:
			// FlareSolverr convention: a page with no challenge is still a
			// successful request.get; return the page itself.
			return types.NewOK("Challenge not detected.", d.Version, sessionID, &types.Solution{URL: "", Status: 200})
		case tperr.CategoryUnsupported:
			return types.NewError(fmt.Sprintf("Cannot solve this challenge: %v", err), d.Version)
		default:
			return types.NewError(err.Error(), d.Version)
		}
	}
	return types.NewError(err.Error(), d.Version)
}

// SolverBrowserUA returns the user-agent the solver is using, or empty.
func (d *Dispatcher) SolverBrowserUA() string {
	if d.Solver == nil {
		return ""
	}
	return ""
}

// ParseRequest decodes a FlareSolverr JSON request from r.
func ParseRequest(r io.Reader) (types.Request, error) {
	var req types.Request
	dec := json.NewDecoder(r)
	if err := dec.Decode(&req); err != nil {
		return req, err
	}
	return req, nil
}

// WriteResponse writes resp as JSON to w.
func WriteResponse(w http.ResponseWriter, resp types.Response) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ResolveProxyURL extracts a proxy URL from the FlareSolverr proxy object.
func ResolveProxyURL(p map[string]string) string {
	if p == nil {
		return ""
	}
	server, ok := p["server"]
	if !ok || server == "" {
		return ""
	}
	u, err := url.Parse(server)
	if err != nil {
		return server
	}
	if user, ok := p["user"]; ok {
		if pass, ok := p["pass"]; ok {
			u.User = url.UserPassword(user, pass)
		} else {
			u.User = url.User(user)
		}
	}
	return u.String()
}
