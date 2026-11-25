package challenge

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// DecodeAaString decodes a string using the aa() obfuscation function found
// in Cloudflare's challenge orchestrator scripts.
//
// The aa() function:
//  1. Base64-decodes the input string using atob()
//  2. Uses a rolling 16-bit XOR key starting at 8185
//  3. Each step: rotate key (k = (k<<8 | k>>8) & 0xFFFF), XOR with k>>8
//  4. If the result is 255, reads a second byte (with another key rotation)
//     and combines them as a 16-bit value
//  5. Collects bytes into a buffer of 128, flushing via fromCharCode
func DecodeAaString(encoded string) (string, error) {
	// Base64-decode the input.
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	// Decode using the rolling XOR key.
	key := uint16(8185)
	var result []uint16
	var buffer []uint16

	for i := 0; i < len(decoded); {
		// Rotate key: k = (k<<8 | k>>8) & 0xFFFF
		key = (key<<8 | key>>8) & 0xFFFF

		if i >= len(decoded) {
			break
		}
		h := uint16(decoded[i]) ^ (key >> 8)
		i++

		if h == 255 {
			// Multi-byte sequence.
			key = (key<<8 | key>>8) & 0xFFFF
			if i >= len(decoded) {
				break
			}
			h = uint16(decoded[i]) ^ (key >> 8)
			i++

			key = (key<<8 | key>>8) & 0xFFFF
			if i >= len(decoded) {
				break
			}
			h |= (uint16(decoded[i]) ^ (key >> 8)) << 8
			i++
		}

		buffer = append(buffer, h)
		if len(buffer) == 128 {
			result = append(result, buffer...)
			buffer = buffer[:0]
		}
	}
	result = append(result, buffer...)

	// Convert UTF-16 code units to a Go string.
	runes := make([]rune, 0, len(result))
	for _, u := range result {
		if u >= 0xD800 && u <= 0xDBFF {
			// High surrogate - would need the next code unit.
			runes = append(runes, rune(u))
		} else {
			runes = append(runes, rune(u))
		}
	}
	return string(runes), nil
}

// rxAaCall matches aa(`...`) calls in the orchestrator script.
var rxAaCall = regexp.MustCompile("aa\\(`([^`]+)`\\)")

// DecodeAllAaCalls finds all aa(`...`) calls in the source and decodes them.
// Returns a map from the encoded string to the decoded value.
func DecodeAllAaCalls(source string) map[string]string {
	results := make(map[string]string)
	for _, m := range rxAaCall.FindAllStringSubmatch(source, -1) {
		if len(m) >= 2 {
			encoded := m[1]
			if decoded, err := DecodeAaString(encoded); err == nil {
				results[encoded] = decoded
			}
		}
	}
	return results
}

// ExtractEncoderParamsDeobfuscated extracts encoder parameters from the
// orchestrator script by first decoding the aa() obfuscated strings.
//
// This is a more advanced version of ExtractEncoderParams that handles
// Cloudflare's string array obfuscation.
func ExtractEncoderParamsDeobfuscated(source string) (*EncoderParams, error) {
	// Decode all aa() calls.
	decoded := DecodeAllAaCalls(source)

	// Build a version of the source with decoded strings.
	deobfuscated := source
	for encoded, value := range decoded {
		deobfuscated = strings.ReplaceAll(deobfuscated, "aa(`"+encoded+"`)",
			"`"+value+"`")
	}

	// Now try to extract encoder parameters from the deobfuscated source.
	return ExtractEncoderParams(deobfuscated)
}
