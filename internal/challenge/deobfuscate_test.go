package challenge

import (
	"testing"
)

func TestDecodeAaString(t *testing.T) {
	// Test with a known aa() encoded string from the orchestrator.
	// The aa() function base64-decodes then XOR-decodes with a rolling key.
	// Let's test with a simple case first.
	cases := []struct {
		name    string
		encoded string
	}{
		{"simple1", "mlatdpR6qg=="},
		{"simple2", "pnyfQJp3lUCWb40="},
		{"simple3", "pi+BL50nynrP"},
		{"simple4", "nX6LdJRwnXo="},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			decoded, err := DecodeAaString(c.encoded)
			if err != nil {
				t.Fatalf("DecodeAaString: %v", err)
			}
			t.Logf("decoded: %q", decoded)
			if len(decoded) == 0 {
				t.Error("decoded string is empty")
			}
		})
	}
}

func TestDecodeAllAaCalls(t *testing.T) {
	source := "var x = aa(`mlatdpR6qg==`);\nvar y = aa(`pnyfQJp3lUCWb40=`);\nvar z = aa(`mlatdpR6qg==`);"
	results := DecodeAllAaCalls(source)
	if len(results) != 2 {
		t.Errorf("expected 2 unique decoded strings, got %d", len(results))
	}
	for encoded, decoded := range results {
		t.Logf("aa(`%s`) = %q", encoded, decoded)
	}
}
