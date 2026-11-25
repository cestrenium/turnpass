// Package fingerprint parses cfsolve-compatible browser profile JSON files.
//
// A fingerprint describes everything a solve needs to impersonate a particular
// browser: the rendering engine family, the TLS/HTTP transport profile, the
// request header order for each request kind, the page layout, the timing
// schedules, the orchestrator pacing, the resource-timing reporting, the
// interaction viewport, and the second-stage probe answers.
//
// Unknown keys are ignored, mirroring the original serde behavior. Each
// program reads only the sections it needs. Required fields are validated
// before any network requests are made.
package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Engine is the browser engine family.
type Engine string

const (
	EngineChromium Engine = "chromium"
	EngineWebKit   Engine = "webkit"
)

// Fingerprint is the parsed profile file.
type Fingerprint struct {
	Engine               Engine           `json:"engine"`
	Transport            TransportSection `json:"transport"`
	Browser              Layout           `json:"browser"`
	Timeline             json.RawMessage  `json:"timeline"`
	Intervals            json.RawMessage  `json:"intervals"`
	Orchestrator         json.RawMessage  `json:"orchestrator"`
	ResourceTiming       json.RawMessage  `json:"resource_timing"`
	Interaction          json.RawMessage  `json:"interaction"`
	Second               json.RawMessage  `json:"second"`
	Answers              string           `json:"answers,omitempty"`
	ChallengePageAnswers string           `json:"challenge_page_answers,omitempty"`
}

// TransportSection is the fingerprint's transport block.
type TransportSection struct {
	Profile     string            `json:"profile"`
	Platform    string            `json:"platform"`
	Headers     map[string]string `json:"headers,omitempty"`
	ClientHello json.RawMessage   `json:"client_hello,omitempty"`
	Requests    Requests          `json:"requests"`
}

// Requests describes per-request-kind header ordering.
type Requests struct {
	Headers map[string][]string `json:"headers"`
}

// Layout is the browser page layout block.
type Layout struct {
	InnerWidth  int          `json:"inner_width"`
	InnerHeight int          `json:"inner_height"`
	Challenge   ChallengeBox `json:"challenge_page"`
	// Raw preserves unrecognised keys for forward compatibility.
	Raw map[string]json.RawMessage `json:"-"`
}

// ChallengeBox is the challenge page checkbox position.
type ChallengeBox struct {
	Top   int `json:"top"`
	Left  int `json:"left"`
	Right int `json:"right"`
}

// ReadFile reads and parses the JSON file at path.
func ReadFile(path string) (*Fingerprint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	fp, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("reading fingerprint JSON %s: %w", path, err)
	}
	return fp, nil
}

// Parse decodes a fingerprint from data. Unknown keys are ignored.
func Parse(data []byte) (*Fingerprint, error) {
	var fp Fingerprint
	if err := json.Unmarshal(data, &fp); err != nil {
		return nil, err
	}
	if err := fp.Validate(); err != nil {
		return nil, err
	}
	return &fp, nil
}

// Validate checks that required fields are present before any network access.
func (fp *Fingerprint) Validate() error {
	if fp.Engine == "" {
		return fmt.Errorf("missing field `engine`")
	}
	if fp.Engine != EngineChromium && fp.Engine != EngineWebKit {
		return fmt.Errorf("unknown variant %q for engine (want %q or %q)", fp.Engine, EngineChromium, EngineWebKit)
	}
	if fp.Transport.Profile == "" {
		return fmt.Errorf("missing field `transport.profile`")
	}
	if fp.Transport.Platform == "" {
		return fmt.Errorf("missing field `transport.platform`")
	}
	if len(fp.Transport.Requests.Headers) == 0 {
		return fmt.Errorf("missing field `transport.requests.headers`")
	}
	// Every declared request kind must list user-agent (the transport fills it in).
	for kind, order := range fp.Transport.Requests.Headers {
		found := false
		for _, h := range order {
			if h == "user-agent" {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("no `user-agent` in `%s` request headers", kind)
		}
	}
	if len(fp.Timeline) == 0 {
		return fmt.Errorf("missing field `timeline`")
	}
	if len(fp.Intervals) == 0 {
		return fmt.Errorf("missing field `intervals`")
	}
	if len(fp.Orchestrator) == 0 {
		return fmt.Errorf("missing field `orchestrator`")
	}
	if len(fp.ResourceTiming) == 0 {
		return fmt.Errorf("missing field `resource_timing`")
	}
	if len(fp.Interaction) == 0 {
		return fmt.Errorf("missing field `interaction`")
	}
	if len(fp.Second) == 0 {
		return fmt.Errorf("missing field `second`")
	}
	return nil
}

// HeaderOrder returns the configured header order for a request kind, or nil.
func (fp *Fingerprint) HeaderOrder(kind string) []string {
	return fp.Transport.Requests.Headers[kind]
}

// UserAgent returns the configured User-Agent header.
func (fp *Fingerprint) UserAgent() string {
	if fp.Transport.Headers != nil {
		if ua, ok := fp.Transport.Headers["User-Agent"]; ok {
			return ua
		}
		if ua, ok := fp.Transport.Headers["user-agent"]; ok {
			return ua
		}
	}
	return ""
}

// LoadAnswers reads the answers file referenced by the fingerprint, resolved
// relative to the fingerprint file's directory. Returns nil if no answers
// file is named.
func (fp *Fingerprint) LoadAnswers(profilePath string) (json.RawMessage, error) {
	return fp.loadRef(profilePath, fp.Answers)
}

// LoadChallengePageAnswers reads the challenge-page answers file.
func (fp *Fingerprint) LoadChallengePageAnswers(profilePath string) (json.RawMessage, error) {
	return fp.loadRef(profilePath, fp.ChallengePageAnswers)
}

func (fp *Fingerprint) loadRef(profilePath, ref string) (json.RawMessage, error) {
	if ref == "" {
		return nil, nil
	}
	dir := filepath.Dir(profilePath)
	p := filepath.Join(dir, filepath.Clean(ref))
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p, err)
	}
	return data, nil
}
