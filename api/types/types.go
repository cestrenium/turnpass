// Package types defines the FlareSolverr-compatible request and response
// structures used by the turnpass-x API server.
//
// Field names and JSON keys follow the upstream FlareSolverr conventions so
// existing FlareSolverr clients can talk to turnpass-x without modification.
package types

import (
	"encoding/json"
	"time"
)

// Request is the top-level FlareSolverr API request.
type Request struct {
	Cmd                 string            `json:"cmd"`
	URL                 string            `json:"url,omitempty"`
	Session             string            `json:"session,omitempty"`
	SessionTTLMinutes   int               `json:"session_ttl_minutes,omitempty"`
	MaxTimeout          int               `json:"maxTimeout,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	PostData            string            `json:"postData,omitempty"`
	Cookies             []Cookie          `json:"cookies,omitempty"`
	ReturnOnlyCookies   bool              `json:"returnOnlyCookies,omitempty"`
	Proxy               map[string]string `json:"proxy,omitempty"`
}

// Cookie is a FlareSolverr cookie entry.
type Cookie struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Domain  string `json:"domain,omitempty"`
	Path    string `json:"path,omitempty"`
	Secure  bool   `json:"secure,omitempty"`
	HttpOnly bool   `json:"httpOnly,omitempty"`
}

// Response is the top-level FlareSolverr API response.
type Response struct {
	Status         string    `json:"status"`
	Message        string    `json:"message"`
	StartTimestamp int64     `json:"startTimestamp"`
	EndTimestamp   int64     `json:"endTimestamp"`
	Version        string    `json:"version"`
	Session        string    `json:"session,omitempty"`
	Solution       *Solution `json:"solution,omitempty"`
}

// Solution is the solved-page payload.
type Solution struct {
	URL     string    `json:"url"`
	Status  int       `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Response *SolutionResponse `json:"response,omitempty"`
	Cookies []Cookie  `json:"cookies"`
	UserAgent string   `json:"userAgent"`
	HTML    string    `json:"html"`
}

// SolutionResponse is the response sub-object (kept for upstream compat).
type SolutionResponse struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Status values.
const (
	StatusOK    = "ok"
	StatusError = "error"
)

// Now returns the current Unix timestamp in milliseconds.
func Now() int64 { return time.Now().UnixMilli() }

// Marshal returns the JSON encoding of r.
func (r *Response) Marshal() ([]byte, error) { return json.Marshal(r) }

// NewOK returns a Response with status=ok and the given message.
func NewOK(msg, version, session string, sol *Solution) Response {
	return Response{
		Status:  StatusOK,
		Message: msg,
		Version: version,
		Session: session,
		Solution: sol,
	}
}

// NewError returns a Response with status=error and the given message.
func NewError(msg, version string) Response {
	return Response{Status: StatusError, Message: msg, Version: version}
}
