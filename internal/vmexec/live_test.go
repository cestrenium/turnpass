//go:build vmexectest

package vmexec

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/cestrenium/turnpass/internal/challenge"
	"github.com/cestrenium/turnpass/internal/deobfuscate"
)

func TestExecuteOrchestratorLive(t *testing.T) {
	// Read the raw orchestrator JS.
	orchJS, err := os.ReadFile("/tmp/turnpass-debug-run/orchestrator.js")
	if err != nil {
		t.Skipf("no orchestrator file: %v", err)
	}

	// Read the challenge page HTML to get _cf_chl_opt values.
	html, err := os.ReadFile("/tmp/test-cf.html")
	if err != nil {
		t.Skipf("no challenge page HTML: %v", err)
	}

	// Extract _cf_chl_opt values.
	cfChlOpt := challenge.ExtractCfChlOptValues(string(html))
	t.Logf("cf_chl_opt values: %d keys", len(cfChlOpt))
	for k, v := range cfChlOpt {
		t.Logf("  %s = %s", k, truncate(v, 40))
	}

	// Deobfuscate to get encoder params (runner name, initial program).
	deobf, err := deobfuscate.DeobfuscateWithInlining(string(orchJS))
	if err != nil {
		t.Fatalf("deobfuscation: %v", err)
	}

	params, err := challenge.ExtractEncoderParams(deobf)
	if err != nil {
		t.Fatalf("extract encoder params: %v", err)
	}
	t.Logf("runner: %q, encoder: %q, initialProgram: %d bytes",
		params.RunnerName, params.Encoder, len(params.InitialProgram))

	if params.RunnerName == "" || params.InitialProgram == "" {
		t.Fatalf("missing runner name or initial program")
	}

	// Execute the orchestrator in goja and call the runner.
	result, err := ExecuteOrchestrator(string(orchJS), params.RunnerName, params.InitialProgram, cfChlOpt)
	if err != nil {
		t.Logf("ExecuteOrchestrator error: %v", err)
	}
	if result == nil {
		t.Fatalf("nil result")
	}

	t.Logf("window keys: %d", len(result.WindowKeys))
	t.Logf("installed globals: %d", len(result.InstalledGlobals))
	t.Logf("options: %d", len(result.Options))

	if result.SecretFound {
		t.Logf("SECRET FOUND: %x (%q)", result.Secret, string(result.Secret[:]))
		t.Logf("key transform: %q", result.KeyTransform)
	} else {
		t.Logf("secret not found directly; scanning installed globals for 16-byte strings...")
		for name, val := range result.InstalledGlobals {
			if s, ok := val.(string); ok && len(s) == 16 {
				t.Logf("  candidate: %s = %q", name, s)
			}
		}
	}

	// Print new globals (installed by the runner call).
	t.Logf("new globals from runner call: %d", len(result.NewGlobals))
	for _, name := range result.NewGlobals {
		val := result.InstalledGlobals[name]
		s := fmt.Sprintf("%v", val)
		if len(s) > 80 {
			s = s[:80] + "..."
		}
		t.Logf("  NEW: window.%s = %s", name, s)
	}

	// Print runner error if any.
	if result.RunnerError != "" {
		t.Logf("runner error: %s", result.RunnerError)
	}
	if result.Error != nil {
		t.Logf("orchestrator error: %v", result.Error)
	}
	if result.RunnerResult != "" {
		s := result.RunnerResult
		if len(s) > 200 {
			s = s[:200] + "..."
		}
		t.Logf("runner result: %s", s)
	}
	// Print new _cf_chl_opt keys.
	t.Logf("new _cf_chl_opt keys from runner call: %d", len(result.NewOptions))
	for _, name := range result.NewOptions {
		t.Logf("  NEW opt: %s = %v", name, result.Options[name])
	}

	// Print some installed globals for debugging.
	count := 0
	for name, val := range result.InstalledGlobals {
		if count < 30 {
			s := fmt.Sprintf("%v", val)
			if len(s) > 60 {
				s = s[:60] + "..."
			}
			t.Logf("  window.%s = %s", name, s)
		}
		count++
	}

	// Try to decode the initial program for reference.
	prog, err := base64.StdEncoding.DecodeString(params.InitialProgram)
	if err == nil {
		t.Logf("initial program decoded: %d bytes", len(prog))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
