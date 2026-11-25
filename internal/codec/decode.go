// Package codec implements the challenge payload encoding and response
// decoding used by Cloudflare's challenge platform.
//
// The encoding wraps a JSON payload in spaces, optionally deflates it,
// frames it with a marker and compression flag, pads to whole 8-byte
// blocks, encrypts with XTEA under a key derived from a random seed, and
// prefixes the seed encrypted with textbook RSA.
//
// Response decoding removes a simpler XOR mask applied to POST responses.
// The mask is derived from the ray token in the request path.
package codec

import (
	"encoding/base64"
	"fmt"
)

// DecodeResponse removes the response mask before the program runs.
// `token` is the ray identifier in the request path `/fo/.../<ray>/...`.
//
// The mask is computed by XOR-folding the token bytes with "_0" starting
// from 32. Each response byte is then unmasked by subtracting the mask
// and a position term (index % 65535), reduced modulo 255.
//
// This mirrors cfsolve's codec::decode_response function.
func DecodeResponse(body []byte, token string) ([]byte, error) {
	if !isASCII(token) {
		return nil, fmt.Errorf("response token must be ASCII")
	}

	// Compute the mask: fold token bytes and "_0" starting from 32.
	mask := byte(32)
	for i := 0; i < len(token); i++ {
		mask ^= token[i]
	}
	mask ^= '_'
	mask ^= '0'

	// Base64-decode the response body.
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return nil, fmt.Errorf("decoding the response envelope: %w", err)
	}

	// Unmask each byte: (byte - mask - (index % 65535)) mod 255.
	// The position term repeats every 65535 bytes, and bytes are reduced
	// modulo 255, not 256.
	result := make([]byte, len(decoded))
	for i, b := range decoded {
		val := int64(b) - int64(mask) - int64(i%65535)
		result[i] = byte(((val % 255) + 255) % 255)
	}
	return result, nil
}

// isASCII reports whether s contains only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
