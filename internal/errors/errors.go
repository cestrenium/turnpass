// Package errors defines the typed error categories used by the turnpass solver.
//
// The categories mirror cfsolve's Error enum so callers can decide whether to
// retry a failed solve. Each category wraps an underlying error chain that
// retains the details.
package errors

import (
	"errors"
	"fmt"
	"io"
	"net"
)

// Category classifies a solve failure.
type Category int

const (
	// CategoryUnknown is the zero value and should not be used directly.
	CategoryUnknown Category = iota
	// CategoryConfig means the profile or options are invalid. Found before any
	// network access. Not retryable.
	CategoryConfig
	// CategoryNetwork means a request failed or timed out. Retryable.
	CategoryNetwork
	// CategoryBlocked means the page answered with an error status and no
	// challenge. Not retryable.
	CategoryBlocked
	// CategoryChallenged means a Turnstile solve received a challenge page
	// instead of the requested page. Retryable after clearing the challenge.
	CategoryChallenged
	// CategoryNotChallenged means the page answered without a challenge page,
	// so there was nothing to clear. Not retryable.
	CategoryNotChallenged
	// CategoryRejected means Cloudflare refused the answers sent at the given
	// stage. Retryable.
	CategoryRejected
	// CategorySink means the Sink failed to save an artifact, so the solve
	// stopped rather than lose its diagnostics.
	CategorySink
	// CategoryUnsupported means the solver cannot handle this page or
	// challenge (for example a new challenge build). Not retryable.
	CategoryUnsupported
)

func (c Category) String() string {
	switch c {
	case CategoryConfig:
		return "config"
	case CategoryNetwork:
		return "network"
	case CategoryBlocked:
		return "blocked"
	case CategoryChallenged:
		return "challenged"
	case CategoryNotChallenged:
		return "not_challenged"
	case CategoryRejected:
		return "rejected"
	case CategorySink:
		return "sink"
	case CategoryUnsupported:
		return "unsupported"
	default:
		return "unknown"
	}
}

// Retryable reports whether a fresh solve with the same profile might succeed.
func (c Category) Retryable() bool {
	switch c {
	case CategoryNetwork, CategoryChallenged, CategoryRejected:
		return true
	default:
		return false
	}
}

// Stage names the payload stage whose answers were refused. Used by Rejected.
type Stage string

const (
	StageProbes      Stage = "probes"
	StageInteraction Stage = "interaction"
	StageProof       Stage = "proof"
)

// Error is a failed solve, or a profile that cannot solve.
type Error struct {
	Category Category
	// Status is the HTTP status of the response that triggered a Blocked or
	// Challenged classification. Zero for other categories.
	Status int
	// Stage is the payload stage refused by Cloudflare for Rejected. Empty for
	// other categories.
	Stage Stage
	// Err is the wrapped error chain retaining the details.
	Err error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	switch e.Category {
	case CategoryBlocked:
		return fmt.Sprintf("the page answered HTTP %d", e.Status)
	case CategoryChallenged:
		return fmt.Sprintf("the page answered HTTP %d with a challenge page; clear it before solving its widget", e.Status)
	case CategoryNotChallenged:
		return "the page answered without a challenge page"
	case CategoryConfig, CategoryNetwork, CategoryRejected, CategorySink, CategoryUnsupported:
		if e.Err != nil {
			return e.Err.Error()
		}
		return e.Category.String()
	default:
		if e.Err != nil {
			return e.Err.Error()
		}
		return "unknown error"
	}
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// NewConfig returns a Config error wrapping err.
func NewConfig(err error) *Error { return &Error{Category: CategoryConfig, Err: err} }

// NewNetwork returns a Network error wrapping err.
func NewNetwork(err error) *Error { return &Error{Category: CategoryNetwork, Err: err} }

// NewBlocked returns a Blocked error with the given HTTP status.
func NewBlocked(status int) *Error { return &Error{Category: CategoryBlocked, Status: status} }

// NewChallenged returns a Challenged error with the given HTTP status.
func NewChallenged(status int) *Error { return &Error{Category: CategoryChallenged, Status: status} }

// NewNotChallenged returns a NotChallenged error.
func NewNotChallenged() *Error { return &Error{Category: CategoryNotChallenged} }

// NewRejected returns a Rejected error at the given stage.
func NewRejected(stage Stage, err error) *Error {
	return &Error{Category: CategoryRejected, Stage: stage, Err: err}
}

// NewSink returns a Sink error wrapping err.
func NewSink(err error) *Error { return &Error{Category: CategorySink, Err: err} }

// NewUnsupported returns an Unsupported error wrapping err.
func NewUnsupported(err error) *Error { return &Error{Category: CategoryUnsupported, Err: err} }

// Classify inspects err and returns the matching Error. Already-classified
// errors pass through. I/O errors count as network failures. Other failures
// are Unsupported.
func Classify(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	// Recognise common network errors.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return NewNetwork(err)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return NewNetwork(err)
	}
	return NewUnsupported(err)
}
