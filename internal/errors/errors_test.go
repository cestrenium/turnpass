package errors

import (
	"errors"
	"io"
	"net"
	"testing"
)

func TestCategoryString(t *testing.T) {
	cases := []struct {
		c    Category
		want string
	}{
		{CategoryConfig, "config"},
		{CategoryNetwork, "network"},
		{CategoryBlocked, "blocked"},
		{CategoryChallenged, "challenged"},
		{CategoryNotChallenged, "not_challenged"},
		{CategoryRejected, "rejected"},
		{CategorySink, "sink"},
		{CategoryUnsupported, "unsupported"},
	}
	for _, c := range cases {
		if got := c.c.String(); got != c.want {
			t.Errorf("Category(%d).String() = %q, want %q", c.c, got, c.want)
		}
	}
}

func TestRetryable(t *testing.T) {
	retryable := []Category{CategoryNetwork, CategoryChallenged, CategoryRejected}
	notRetryable := []Category{CategoryConfig, CategoryBlocked, CategoryNotChallenged, CategorySink, CategoryUnsupported}
	for _, c := range retryable {
		if !c.Retryable() {
			t.Errorf("Category(%s).Retryable() = false, want true", c)
		}
	}
	for _, c := range notRetryable {
		if c.Retryable() {
			t.Errorf("Category(%s).Retryable() = true, want false", c)
		}
	}
}

func TestBlockedDisplay(t *testing.T) {
	e := NewBlocked(403)
	if got := e.Error(); got != "the page answered HTTP 403" {
		t.Errorf("Blocked.Error() = %q", got)
	}
	if e.Status != 403 {
		t.Errorf("Status = %d", e.Status)
	}
}

func TestChallengedDisplay(t *testing.T) {
	e := NewChallenged(503)
	if got := e.Error(); got != "the page answered HTTP 503 with a challenge page; clear it before solving its widget" {
		t.Errorf("Challenged.Error() = %q", got)
	}
}

func TestNotChallengedDisplay(t *testing.T) {
	e := NewNotChallenged()
	if got := e.Error(); got != "the page answered without a challenge page" {
		t.Errorf("NotChallenged.Error() = %q", got)
	}
}

func TestRejectedPreservesStageAndErr(t *testing.T) {
	inner := errors.New("refused")
	e := NewRejected(StageProbes, inner)
	if e.Stage != StageProbes {
		t.Errorf("Stage = %q", e.Stage)
	}
	if !errors.Is(e, inner) {
		t.Errorf("Unwrap lost the inner error")
	}
	if e.Error() != "refused" {
		t.Errorf("Error() = %q", e.Error())
	}
	if !e.Category.Retryable() {
		t.Errorf("Rejected should be retryable")
	}
}

func TestClassify(t *testing.T) {
	// Pass-through for already-classified errors.
	blocked := NewBlocked(403)
	if Classify(blocked) != blocked {
		t.Errorf("Classify did not pass through a blocked error")
	}
	// Net errors become Network.
	netErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	c := Classify(netErr)
	if c.Category != CategoryNetwork {
		t.Errorf("Classify(netErr) = %s, want network", c.Category)
	}
	// EOF becomes Network.
	c = Classify(io.ErrUnexpectedEOF)
	if c.Category != CategoryNetwork {
		t.Errorf("Classify(EOF) = %s, want network", c.Category)
	}
	// Anything else becomes Unsupported.
	c = Classify(errors.New("no orchestrator path"))
	if c.Category != CategoryUnsupported {
		t.Errorf("Classify(unknown) = %s, want unsupported", c.Category)
	}
}
