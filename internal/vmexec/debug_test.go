//go:build vmexectest

package vmexec

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/cestrenium/turnpass/internal/challenge"
	"github.com/cestrenium/turnpass/internal/deobfuscate"
)

func TestDebugRunner(t *testing.T) {
	orchJS, _ := os.ReadFile("/tmp/turnpass-debug-run/orchestrator.js")
	deobf, err := deobfuscate.DeobfuscateWithInlining(string(orchJS))
	if err != nil {
		t.Fatalf("deobfuscation: %v", err)
	}
	params, err := challenge.ExtractEncoderParams(deobf)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	t.Logf("runner: %q, encoder: %q, program: %d bytes", params.RunnerName, params.Encoder, len(params.InitialProgram))

	// Search for runner calls in the source
	runnerName := params.RunnerName
	// Pattern: runnerName(`...`) or runnerName("...") or obj.runnerName(`...`)
	patterns := []string{
		runnerName + "\\(`",
		runnerName + "\\(\"",
		runnerName + "\\('",
		"\\." + runnerName + "\\(`",
		"\\." + runnerName + "\\(\"",
	}
	for _, p := range patterns {
		rx := regexp.MustCompile(p)
		matches := rx.FindAllString(deobf, -1)
		t.Logf("pattern %q: %d matches", p, len(matches))
		if len(matches) > 0 {
			// Find the context
			idx := rx.FindStringIndex(deobf)
			if idx != nil {
				start := idx[0]
				end := start + 200
				if end > len(deobf) {
					end = len(deobf)
				}
				t.Logf("  context: %s", deobf[start:end])
			}
		}
	}

	// Also check raw source
	for _, p := range patterns {
		rx := regexp.MustCompile(p)
		matches := rx.FindAllString(string(orchJS), -1)
		t.Logf("RAW pattern %q: %d matches", p, len(matches))
		if len(matches) > 0 {
			idx := rx.FindStringIndex(string(orchJS))
			if idx != nil {
				start := idx[0]
				end := start + 200
				if end > len(string(orchJS)) {
					end = len(string(orchJS))
				}
				t.Logf("  context: %s", string(orchJS)[start:end])
			}
		}
	}
	fmt.Println("done")
}
