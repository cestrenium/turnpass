package challenge

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// EncoderParams holds the session's encoding constants extracted from the
// iframe JavaScript: the base64 alphabet, RSA modulus, and key-transform
// secret.
type EncoderParams struct {
	// Alphabet is the 64-character base64 alphabet used by the session.
	Alphabet string
	// Modulus is the RSA modulus (1024-bit) used to encrypt the seed.
	Modulus *big.Int
	// Secret is the 16-byte key-transform secret.
	Secret [16]byte
	// KeyTransform is the name of the function the VM defines at runtime
	// that applies the key transform.
	KeyTransform string
	// Encoder is the name of the function whose result is handed to send().
	Encoder string
}

var (
	// Matches BigInt("0x...") calls.
	rxBigInt = regexp.MustCompile(`BigInt\s*\(\s*["']0x([0-9a-fA-F]+)["']\s*\)`)
	// Matches string literals that could be base64 alphabets (64 distinct chars).
	rxString64 = regexp.MustCompile(`["']([A-Za-z0-9+/=_\-]{64,65})["']`)
	// Matches string literals of exactly 16 characters (potential key secrets).
	rxString16 = regexp.MustCompile(`["']([^"']{16})["']`)
)

// ExtractEncoderParams scans the iframe JavaScript source for the session's
// encoding constants: the base64 alphabet, RSA modulus, and key-transform
// secret.
//
// This is a simplified version that uses regex scanning rather than full AST
// analysis. The full cfsolve implementation uses Oxc's AST to find these
// values more reliably.
func ExtractEncoderParams(iframeJS string) (*EncoderParams, error) {
	params := &EncoderParams{}

	// Find the RSA modulus: BigInt("0x...") with a 1024-bit (128-byte) modulus.
	for _, m := range rxBigInt.FindAllStringSubmatch(iframeJS, -1) {
		if len(m) >= 2 {
			hexStr := m[1]
			modulus, ok := new(big.Int).SetString(hexStr, 16)
			if !ok {
				continue
			}
			// Check if it's 1024 bits (128 bytes).
			if modulus.BitLen() > 0 && (modulus.BitLen()+7)/8 == 128 {
				params.Modulus = modulus
				break
			}
		}
	}

	// Find the base64 alphabet: a string with 64 distinct ASCII characters.
	for _, m := range rxString64.FindAllStringSubmatch(iframeJS, -1) {
		if len(m) >= 2 {
			candidate := m[1]
			if len(candidate) >= 64 {
				candidate = candidate[:64]
			}
			if isDistinctASCII(candidate) && len(candidate) == 64 {
				params.Alphabet = candidate
				break
			}
		}
	}

	// Find the key-transform secret: a 16-character string.
	// This is typically found near charCodeAt calls or in the initial VM program.
	for _, m := range rxString16.FindAllStringSubmatch(iframeJS, -1) {
		if len(m) >= 2 {
			secret := m[1]
			if len(secret) == 16 && isPrintableASCII(secret) {
				for i, c := range []byte(secret) {
					params.Secret[i] = c
				}
				break
			}
		}
	}

	// Validate that we found the required parameters.
	if params.Modulus == nil {
		return nil, fmt.Errorf("could not find RSA modulus in iframe JS")
	}
	if params.Alphabet == "" {
		return nil, fmt.Errorf("could not find base64 alphabet in iframe JS")
	}

	return params, nil
}

// isDistinctASCII checks whether s consists of 64 distinct ASCII characters.
func isDistinctASCII(s string) bool {
	if len(s) != 64 {
		return false
	}
	seen := make(map[byte]bool)
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
		if seen[s[i]] {
			return false
		}
		seen[s[i]] = true
	}
	return true
}

// isPrintableASCII checks whether s consists of printable ASCII characters.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}

// ModulusHex returns the RSA modulus as a hex string.
func (p *EncoderParams) ModulusHex() string {
	if p.Modulus == nil {
		return ""
	}
	return hex.EncodeToString(p.Modulus.Bytes())
}

// String returns a description of the encoder parameters.
func (p *EncoderParams) String() string {
	modulusBits := 0
	if p.Modulus != nil {
		modulusBits = p.Modulus.BitLen()
	}
	return fmt.Sprintf("EncoderParams{alphabet: %d chars, modulus: %d bits, secret: %d bytes}",
		len(p.Alphabet), modulusBits, len(p.Secret))
}

// HasAllParams reports whether all required parameters were found.
func (p *EncoderParams) HasAllParams() bool {
	return p.Modulus != nil && p.Alphabet != "" && p.Secret != [16]byte{}
}

// FindAlphabetCandidates finds all string literals in the source that could be
// base64 alphabets.
func FindAlphabetCandidates(source string) []string {
	var candidates []string
	for _, m := range rxString64.FindAllStringSubmatch(source, -1) {
		if len(m) >= 2 {
			candidate := m[1]
			if len(candidate) >= 64 {
				candidate = candidate[:64]
			}
			if isDistinctASCII(candidate) {
				candidates = append(candidates, candidate)
			}
		}
	}
	return candidates
}

// FindModulusCandidates finds all BigInt("0x...") calls in the source.
func FindModulusCandidates(source string) []*big.Int {
	var moduli []*big.Int
	for _, m := range rxBigInt.FindAllStringSubmatch(source, -1) {
		if len(m) >= 2 {
			modulus, ok := new(big.Int).SetString(m[1], 16)
			if ok && modulus.BitLen() > 0 {
				moduli = append(moduli, modulus)
			}
		}
	}
	return moduli
}

// FindSecretCandidates finds all 16-character string literals in the source.
func FindSecretCandidates(source string) []string {
	var candidates []string
	for _, m := range rxString16.FindAllStringSubmatch(source, -1) {
		if len(m) >= 2 && len(m[1]) == 16 && isPrintableASCII(m[1]) {
			candidates = append(candidates, m[1])
		}
	}
	return candidates
}

// EncodeModulusHex encodes a big.Int as a 0x-prefixed hex string.
func EncodeModulusHex(n *big.Int) string {
	return "0x" + strings.ToLower(hex.EncodeToString(n.Bytes()))
}
