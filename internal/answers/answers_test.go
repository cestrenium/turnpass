package answers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseAnswers(t *testing.T) {
	// Test with inline JSON.
	data := []byte(`{
  "reference": "e25ccf38995a05af",
  "probes": {
    "2": {
      "duration": 73,
      "fields": {
        "test_field": [1, 2, 3]
      }
    },
    "3": {
      "duration": 12,
      "fields": {
        "other": "value"
      }
    }
  },
  "navigator": {
    "platform": "iPhone",
    "languages": ["en-US"],
    "hardwareConcurrency": 4,
    "userAgent": "Mozilla/5.0 Test"
  },
  "globals": {
    "_abc": {"kind": "test"}
  },
  "stylesheets": [
    {"source": "test.css", "rules": []}
  ]
}`)

	a, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if a.Reference != "e25ccf38995a05af" {
		t.Errorf("Reference = %q", a.Reference)
	}
	if len(a.Probes) != 2 {
		t.Errorf("Probes count = %d, want 2", len(a.Probes))
	}
	if a.Navigator.HardwareConcurrency != 4 {
		t.Errorf("HC = %d", a.Navigator.HardwareConcurrency)
	}
	if a.Navigator.Platform != "iPhone" {
		t.Errorf("Platform = %q", a.Navigator.Platform)
	}
	if len(a.Navigator.Languages) != 1 || a.Navigator.Languages[0] != "en-US" {
		t.Errorf("Languages = %v", a.Navigator.Languages)
	}
	if len(a.Globals) != 1 {
		t.Errorf("Globals count = %d", len(a.Globals))
	}
	if len(a.Stylesheets) != 1 {
		t.Errorf("Stylesheets count = %d", len(a.Stylesheets))
	}
}

func TestCheck(t *testing.T) {
	// Valid answers.
	a := &Answers{
		Reference: "test",
		Navigator: Navigator{HardwareConcurrency: 4, UserAgent: "test"},
	}
	if err := a.Check(); err != nil {
		t.Errorf("Check failed for valid answers: %v", err)
	}

	// Missing reference.
	a.Reference = ""
	if err := a.Check(); err == nil {
		t.Error("Check should fail for missing reference")
	}

	// Missing hardwareConcurrency.
	a.Reference = "test"
	a.Navigator.HardwareConcurrency = 0
	if err := a.Check(); err == nil {
		t.Error("Check should fail for missing HC")
	}
}

func TestGetProbe(t *testing.T) {
	a := &Answers{
		Probes: map[string]Probe{
			"5": {Duration: 42, Fields: map[string]json.RawMessage{"key": json.RawMessage(`"value"`)}},
		},
	}

	p, err := a.GetProbe("5")
	if err != nil {
		t.Fatalf("GetProbe: %v", err)
	}
	if p.Duration != 42 {
		t.Errorf("Duration = %d", p.Duration)
	}

	_, err = a.GetProbe("999")
	if err == nil {
		t.Error("GetProbe should fail for missing probe")
	}
}

func TestLoadRealProfile(t *testing.T) {
	// Test loading the real upstream profile if available.
	path := "/tmp/cf-profiles/safari-26-ios/answers.json"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("profile not available at %s", path)
	}

	a, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if err := a.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}

	t.Logf("Loaded: %s", a.String())

	if a.Reference != "e25ccf38995a05af" {
		t.Errorf("Reference = %q", a.Reference)
	}
	if a.Navigator.HardwareConcurrency != 4 {
		t.Errorf("HC = %d", a.Navigator.HardwareConcurrency)
	}
	if a.Navigator.Platform != "iPhone" {
		t.Errorf("Platform = %q", a.Navigator.Platform)
	}
	if len(a.Probes) < 10 {
		t.Errorf("Probe count = %d, want >= 10", len(a.Probes))
	}
	if len(a.Globals) < 10 {
		t.Errorf("Globals count = %d, want >= 10", len(a.Globals))
	}
}

func TestLoadFromProfileDir(t *testing.T) {
	// Test loading answers from a profile directory (like cfsolve does).
	profilePath := "/tmp/cf-profiles/safari-26-ios.json"
	if _, err := os.Stat(profilePath); err != nil {
		t.Skipf("profile not available")
	}

	// The answers file is referenced relative to the profile directory.
	// In the upstream profile, "answers": "safari-26-ios/answers.json"
	// means we need to join the profile's directory with the answers path.
	dir := filepath.Dir(profilePath)
	answersPath := filepath.Join(dir, "safari-26-ios", "answers.json")

	a, err := Load(answersPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if err := a.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}

	t.Logf("Profile dir: %s", dir)
	t.Logf("Answers: %s", a.String())
}
