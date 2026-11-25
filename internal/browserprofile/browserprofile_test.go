package browserprofile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cestrenium/turnpass/internal/fingerprint"
)

const profileJSON = `{
  "engine": "webkit",
  "transport": {
    "profile": "safari_ios_26.2",
    "platform": "ios",
    "headers": {"User-Agent": "TestUA"},
    "requests": {"headers": {"navigation": ["user-agent"]}}
  },
  "timeline": {},
  "intervals": {},
  "orchestrator": {},
  "resource_timing": {},
  "interaction": {},
  "second": {}
}`

func TestReadFromDisk(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "test.json")
	if err := os.WriteFile(profilePath, []byte(profileJSON), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	answersPath := filepath.Join(dir, "answers.json")
	if err := os.WriteFile(answersPath, []byte(`{"navigator":{}}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Patch profile to reference answers.
	patched := `{
  "engine": "webkit",
  "transport": {"profile": "safari_ios_26.2", "platform": "ios", "headers": {"User-Agent": "TestUA"}, "requests": {"headers": {"navigation": ["user-agent"]}}},
  "timeline": {}, "intervals": {}, "orchestrator": {}, "resource_timing": {}, "interaction": {}, "second": {},
  "answers": "answers.json"
}`
	if err := os.WriteFile(profilePath, []byte(patched), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	b, err := Read(profilePath)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if b.Engine() != fingerprint.EngineWebKit {
		t.Errorf("Engine = %q", b.Engine())
	}
	if b.UserAgent() != "TestUA" {
		t.Errorf("UserAgent = %q", b.UserAgent())
	}
	if !b.HasAnswers() {
		t.Errorf("HasAnswers = false, want true")
	}
	if b.HasChallengePageAnswers() {
		t.Errorf("HasChallengePageAnswers = true, want false")
	}
}

func TestFromJSON(t *testing.T) {
	b, err := FromJSON([]byte(profileJSON), nil, nil)
	if err != nil {
		t.Fatalf("FromJSON: %v", err)
	}
	if b.HasAnswers() {
		t.Errorf("HasAnswers should be false for nil answers")
	}
}

func TestString(t *testing.T) {
	b, _ := FromJSON([]byte(profileJSON), nil, nil)
	s := b.String()
	if s == "<nil browser>" {
		t.Errorf("String = %q", s)
	}
	var nilB *Browser
	if nilB.String() != "<nil browser>" {
		t.Errorf("nil String = %q", nilB.String())
	}
}
