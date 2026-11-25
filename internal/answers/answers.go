// Package answers implements loading and replaying of recorded probe answers
// from cfsolve-compatible browser profiles.
package answers

import (
	"encoding/json"
	"fmt"
	"os"
)

// Answers holds the recorded probe answers from a browser profile.
type Answers struct {
	Reference   string                     `json:"reference"`
	Probes      map[string]Probe           `json:"probes"`
	Navigator   Navigator                  `json:"navigator"`
	Globals     map[string]json.RawMessage `json:"globals"`
	Stylesheets []Stylesheet               `json:"stylesheets"`
}

// Probe holds the recorded data for one probe.
type Probe struct {
	Duration int                        `json:"duration"`
	Fields   map[string]json.RawMessage `json:"fields"`
}

// Navigator holds the browser's navigator properties.
type Navigator struct {
	Platform            string   `json:"platform"`
	Languages           []string `json:"languages"`
	HardwareConcurrency int      `json:"hardwareConcurrency"`
	UserAgent           string   `json:"userAgent"`
}

// Stylesheet holds recorded stylesheet data.
type Stylesheet struct {
	Source string          `json:"source"`
	Rules  json.RawMessage `json:"rules"`
}

// Load reads an answers.json file from disk.
func Load(path string) (*Answers, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes answers data from JSON bytes.
func Parse(data []byte) (*Answers, error) {
	var a Answers
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parsing answers JSON: %w", err)
	}
	return &a, nil
}

// Check validates that the answers are internally consistent.
func (a *Answers) Check() error {
	if a.Reference == "" {
		return fmt.Errorf("answers have no reference")
	}
	if a.Navigator.HardwareConcurrency == 0 {
		return fmt.Errorf("answers have no hardwareConcurrency")
	}
	if a.Navigator.UserAgent == "" {
		return fmt.Errorf("answers have no userAgent")
	}
	return nil
}

// ProbeCount returns the number of recorded probes.
func (a *Answers) ProbeCount() int { return len(a.Probes) }

// HasProbe reports whether a probe with the given index exists.
func (a *Answers) HasProbe(index string) bool {
	_, ok := a.Probes[index]
	return ok
}

// GetProbe returns the probe data for the given index.
func (a *Answers) GetProbe(index string) (*Probe, error) {
	p, ok := a.Probes[index]
	if !ok {
		return nil, fmt.Errorf("probe %s not found", index)
	}
	return &p, nil
}

// ProbeField returns the raw JSON of a specific field within a probe.
func (a *Answers) ProbeField(probeIndex, fieldName string) (json.RawMessage, error) {
	p, err := a.GetProbe(probeIndex)
	if err != nil {
		return nil, err
	}
	field, ok := p.Fields[fieldName]
	if !ok {
		return nil, fmt.Errorf("field %s not found in probe %s", fieldName, probeIndex)
	}
	return field, nil
}

// GlobalNames returns the names of all recorded globals.
func (a *Answers) GlobalNames() []string {
	names := make([]string, 0, len(a.Globals))
	for name := range a.Globals {
		names = append(names, name)
	}
	return names
}

// String returns a summary of the answers.
func (a *Answers) String() string {
	ua := a.Navigator.UserAgent
	if len(ua) > 40 {
		ua = ua[:40]
	}
	return fmt.Sprintf("Answers{ref:%s probes:%d hc:%d ua:%s globals:%d css:%d}",
		a.Reference, len(a.Probes), a.Navigator.HardwareConcurrency,
		ua, len(a.Globals), len(a.Stylesheets))
}
