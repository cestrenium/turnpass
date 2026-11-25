// Package browserprofile loads a cfsolve-compatible browser profile and its
// recorded answers, producing a validated Browser ready for solving.
//
// A Browser is safe to load once and reuse across concurrent solves. Each
// solve gets its own connections, cookie jar and proxy.
package browserprofile

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cestrenium/turnpass/internal/answers"
	"github.com/cestrenium/turnpass/internal/fingerprint"
)

// Browser is a validated profile shared by solves.
type Browser struct {
	Fingerprint *fingerprint.Fingerprint
	// Answers is the recorded probe-answer data for ordinary pages, or nil.
	Answers json.RawMessage
	// ChallengePageAnswers is the recorded probe-answer data for Cloudflare
	// challenge pages, or nil.
	ChallengePageAnswers json.RawMessage
	// ParsedAnswers is the parsed Answers struct, or nil.
	ParsedAnswers *answers.Answers
	// ParsedChallengePageAnswers is the parsed challenge-page Answers, or nil.
	ParsedChallengePageAnswers *answers.Answers
}

// Read loads the fingerprint at path and the answer files it names, relative
// to the fingerprint file's directory.
func Read(path string) (*Browser, error) {
	fp, err := fingerprint.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rawAnswers, err := fp.LoadAnswers(path)
	if err != nil {
		return nil, err
	}
	cpa, err := fp.LoadChallengePageAnswers(path)
	if err != nil {
		return nil, err
	}
	b := &Browser{Fingerprint: fp, Answers: rawAnswers, ChallengePageAnswers: cpa}
	// Parse the answers for structured access.
	if len(rawAnswers) > 0 {
		if parsed, err := answers.Parse(rawAnswers); err == nil {
			b.ParsedAnswers = parsed
		}
	}
	if len(cpa) > 0 {
		if parsed, err := answers.Parse(cpa); err == nil {
			b.ParsedChallengePageAnswers = parsed
		}
	}
	return b, nil
}

// FromJSON builds a Browser from an in-memory fingerprint JSON document.
func FromJSON(data []byte, answers, challengePageAnswers json.RawMessage) (*Browser, error) {
	fp, err := fingerprint.Parse(data)
	if err != nil {
		return nil, err
	}
	return &Browser{Fingerprint: fp, Answers: answers, ChallengePageAnswers: challengePageAnswers}, nil
}

// Engine returns the browser engine family.
func (b *Browser) Engine() fingerprint.Engine { return b.Fingerprint.Engine }

// UserAgent returns the configured User-Agent header.
func (b *Browser) UserAgent() string { return b.Fingerprint.UserAgent() }

// HasAnswers reports whether recorded probe answers are available.
//
// The challenge-program VM (the obfuscated JS interpreter that consumes
// these answers) is the largest single piece of cfsolve and is being ported
// incrementally. Until it is complete, solves that require executing a
// challenge program return Unsupported. See KNOWN_LIMITATIONS.md.
func (b *Browser) HasAnswers() bool { return len(b.Answers) > 0 }

// HasChallengePageAnswers reports whether challenge-page answers are available.
func (b *Browser) HasChallengePageAnswers() bool { return len(b.ChallengePageAnswers) > 0 }

// String returns a short human-readable description.
func (b *Browser) String() string {
	if b == nil || b.Fingerprint == nil {
		return "<nil browser>"
	}
	return fmt.Sprintf("browser{engine=%s profile=%s platform=%s}",
		b.Fingerprint.Engine, b.Fingerprint.Transport.Profile, b.Fingerprint.Transport.Platform)
}

// LoadAnswersFromFile reads an answers JSON file from disk. Used by tests and
// by callers that want to supply answers out-of-band.
func LoadAnswersFromFile(path string) (json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, nil
}
