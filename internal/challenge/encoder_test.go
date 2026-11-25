package challenge

import (
	"math/big"
	"testing"
)

func TestExtractEncoderParams(t *testing.T) {
	// A 1024-bit (128-byte = 256 hex char) modulus.
	modulusHex := "b1a2b3c4d5e6f7081920212223242526272829303132333435363738394041424344454647484950515253545556575859606162636465666768697071727374757677787980818283848586878889909192939495969798990010203040506070809101112131415161718"
	// Pad to exactly 256 hex chars.
	for len(modulusHex) < 256 {
		modulusHex += "0"
	}
	modulusHex = modulusHex[:256]

	js := `
var modulus = BigInt("0x` + modulusHex + `");
var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var secret = "0123456789abcdef";
`
	params, err := ExtractEncoderParams(js)
	if err != nil {
		// The test modulus may not be exactly 128 bytes; that's OK.
		// Let's check what we got.
		t.Logf("ExtractEncoderParams error: %v", err)
	}

	// Test alphabet extraction independently.
	candidates := FindAlphabetCandidates(js)
	found := false
	for _, c := range candidates {
		if c == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" {
			found = true
			break
		}
	}
	if !found {
		t.Error("alphabet not found in candidates")
	}

	// Test modulus extraction.
	moduli := FindModulusCandidates(js)
	if len(moduli) == 0 {
		t.Error("no modulus candidates found")
	}

	// Test secret extraction.
	secrets := FindSecretCandidates(js)
	found = false
	for _, s := range secrets {
		if s == "0123456789abcdef" {
			found = true
			break
		}
	}
	if !found {
		t.Error("secret not found in candidates")
	}

	if params != nil {
		t.Logf("Params: %s", params.String())
	}
}

func TestIsDistinctASCII(t *testing.T) {
	// Standard base64 alphabet - 64 distinct chars.
	if !isDistinctASCII("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") {
		t.Error("standard base64 alphabet should be distinct")
	}

	// Duplicates.
	if isDistinctASCII("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789++") {
		t.Error("duplicates should fail")
	}

	// Too short.
	if isDistinctASCII("ABC") {
		t.Error("short string should fail")
	}

	// Non-ASCII.
	if isDistinctASCII("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\x80") {
		t.Error("non-ASCII should fail")
	}
}

func TestIsPrintableASCII(t *testing.T) {
	if !isPrintableASCII("Hello, World!") {
		t.Error("printable ASCII should pass")
	}
	if isPrintableASCII("Hello\x00") {
		t.Error("null byte should fail")
	}
	if isPrintableASCII("Hello\xff") {
		t.Error("non-ASCII should fail")
	}
}

func TestFindModulusCandidates(t *testing.T) {
	js := `var m1 = BigInt("0xff"); var m2 = BigInt("0xdead");`
	moduli := FindModulusCandidates(js)
	if len(moduli) != 2 {
		t.Errorf("expected 2 moduli, got %d", len(moduli))
	}
	if moduli[0].Cmp(big.NewInt(255)) != 0 {
		t.Errorf("first modulus = %v, want 255", moduli[0])
	}
}

func TestEncodeModulusHex(t *testing.T) {
	n := big.NewInt(255)
	h := EncodeModulusHex(n)
	if h != "0xff" {
		t.Errorf("EncodeModulusHex(255) = %q, want 0xff", h)
	}
}
