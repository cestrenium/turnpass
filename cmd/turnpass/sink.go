package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/cestrenium/turnpass/internal/solver"
)

// verboseSink writes progress to stderr and (optionally) saves artifacts to
// a directory. It is safe for concurrent use.
type verboseSink struct {
	w       io.Writer
	debugDir string
	mu      sync.Mutex
}

func newVerboseSink(w io.Writer, debugDir string) *verboseSink {
	return &verboseSink{w: w, debugDir: debugDir}
}

func (v *verboseSink) Progress(msg string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	fmt.Fprintf(v.w, "turnpass: %s\n", msg)
}

func (v *verboseSink) Artifact(name string, data []byte) error {
	if v.debugDir == "" {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := os.MkdirAll(v.debugDir, 0o755); err != nil {
		return err
	}
	p := filepath.Join(v.debugDir, filepath.Clean(name))
	return os.WriteFile(p, data, 0o644)
}

// errorsAs wraps errors.As so the main package can keep its import list small.
func errorsAs(err error, target any) bool { return errors.As(err, target) }

// Compile-time check that verboseSink satisfies solver.Sink.
var _ solver.Sink = (*verboseSink)(nil)
