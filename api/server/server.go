// Package server implements the turnpass-x HTTP server.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/cestrenium/turnpass/api/handlers"
	"github.com/cestrenium/turnpass/api/middleware"
		"github.com/cestrenium/turnpass/api/sessions"
	"github.com/cestrenium/turnpass/api/types"
)

// Config holds the server configuration.
type Config struct {
	Addr               string        // host:port
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	IdleTimeout        time.Duration
	RequestTimeout     time.Duration
	SessionDefaultTTL  time.Duration
	Version            string
}

// Server is the turnpass-x HTTP server.
type Server struct {
	cfg        Config
	dispatcher *handlers.Dispatcher
	store      *sessions.Store
	httpSrv    *http.Server
}

// New builds a Server.
func New(cfg Config, dispatcher *handlers.Dispatcher, store *sessions.Store) *Server {
	if cfg.Addr == "" {
		cfg.Addr = ":8191"
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 10 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 60 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 120 * time.Second
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 5 * time.Minute
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	return &Server{cfg: cfg, dispatcher: dispatcher, store: store}
}

// Routes returns the configured http.Handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/", s.handleAPI)
	mux.HandleFunc("/v1", s.handleAPI)
	var h http.Handler = mux
	h = middleware.Timeout(s.cfg.RequestTimeout)(h)
	h = middleware.Recovery(h)
	h = middleware.Logging(h)
	return h
}

// ListenAndServe starts the server. Blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.httpSrv = &http.Server{
		Addr:         s.cfg.Addr,
		Handler:      s.Routes(),
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: s.cfg.WriteTimeout,
		IdleTimeout:  s.cfg.IdleTimeout,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutdownCtx)
	}()
	log.Printf("turnpass-x listening on %s", s.cfg.Addr)
	err := s.httpSrv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{
		"status":  "ok",
		"version": s.cfg.Version,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req, err := handlers.ParseRequest(r.Body)
	if err != nil {
		writeAPIError(w, s.cfg.Version, "invalid JSON: "+err.Error())
		return
	}
	if req.Cmd == "" {
		writeAPIError(w, s.cfg.Version, "cmd is required")
		return
	}
	resp := s.dispatcher.Handle(r.Context(), req)
	handlers.WriteResponse(w, resp)
}

func writeAPIError(w http.ResponseWriter, version, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	resp := types.NewError(msg, version)
	resp.StartTimestamp = types.Now()
	resp.EndTimestamp = types.Now()
	_ = json.NewEncoder(w).Encode(resp)
}
