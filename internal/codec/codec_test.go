package codec

import (
	"encoding/base64"
	"math/big"
	"testing"
)

func TestDecodeResponseRoundTrip(t *testing.T) {
	// Test the response decoding with a known token and plaintext.
	token := "abcdef0123456789"

	// Compute the mask the same way decode_response does.
	mask := byte(32)
	for i := 0; i < len(token); i++ {
		mask ^= token[i]
	}
	mask ^= '_'
	mask ^= '0'

	// Create plaintext and mask it.
	plaintext := make([]byte, 100)
	for i := range plaintext {
		plaintext[i] = byte(i % 254)
	}
	masked := make([]byte, len(plaintext))
	for i, b := range plaintext {
		masked[i] = byte((int(b) + int(mask) + i%65535) % 255)
	}

	// Base64-encode the masked bytes.
	encoded := base64.StdEncoding.EncodeToString(masked)

	// Decode and verify.
	result, err := DecodeResponse([]byte(encoded), token)
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if len(result) != len(plaintext) {
		t.Fatalf("length = %d, want %d", len(result), len(plaintext))
	}
	for i := range plaintext {
		if result[i] != plaintext[i] {
			t.Errorf("byte %d: got %d, want %d", i, result[i], plaintext[i])
		}
	}
}

func TestDecodeResponsePositionWraps(t *testing.T) {
	// Test that the position term wraps at 65535.
	token := "abcdef0123456789"
	mask := byte(32)
	for i := 0; i < len(token); i++ {
		mask ^= token[i]
	}
	mask ^= '_'
	mask ^= '0'

	plaintext := make([]byte, 65538)
	for i := range plaintext {
		plaintext[i] = byte(i % 254)
	}
	masked := make([]byte, len(plaintext))
	for i, b := range plaintext {
		masked[i] = byte((int(b) + int(mask) + i%65535) % 255)
	}
	encoded := base64.StdEncoding.EncodeToString(masked)

	result, err := DecodeResponse([]byte(encoded), token)
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	for i := range plaintext {
		if result[i] != plaintext[i] {
			t.Errorf("byte %d: got %d, want %d", i, result[i], plaintext[i])
		}
	}
}

func TestDecodeResponseNonASCIIToken(t *testing.T) {
	_, err := DecodeResponse([]byte("test"), "tökën")
	if err == nil {
		t.Fatal("expected error for non-ASCII token")
	}
}

func TestXTEARoundTrip(t *testing.T) {
	// Test that encrypting then decrypting recovers the original.
	key := [KeyLength]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	base := schedule(words16(key[:]))

	original := [2]uint32{0x12345678, 0x9ABCDEF0}
	encrypted := EncryptBlock(original, &base)
	decrypted := DecryptBlock(encrypted, &base)

	if decrypted != original {
		t.Errorf("round-trip failed: got %v, want %v", decrypted, original)
	}
}

func TestXTEANonZeroKey(t *testing.T) {
	// Test with a different key to ensure it's not trivially identity.
	key1 := [KeyLength]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	key2 := [KeyLength]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	base1 := schedule(words16(key1[:]))
	base2 := schedule(words16(key2[:]))

	block := [2]uint32{0xDEADBEEF, 0xCAFEBABE}
	enc1 := EncryptBlock(block, &base1)
	enc2 := EncryptBlock(block, &base2)

	if enc1 == enc2 {
		t.Error("different keys should produce different ciphertext")
	}
	if enc1 == block {
		t.Error("encryption should not be identity")
	}
}

func TestFrameKey(t *testing.T) {
	seed := make([]byte, 128)
	for i := range seed {
		seed[i] = byte(i)
	}
	secret := [KeyLength]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	// padding=0: start=40
	key0 := FrameKey(seed, 0, secret)
	start0 := 40
	for i := 0; i < KeyLength; i++ {
		want := seed[start0+i] ^ secret[i]
		if key0[i] != want {
			t.Errorf("key0[%d] = %d, want %d", i, key0[i], want)
		}
	}

	// padding=1: start=49
	key1 := FrameKey(seed, 1, secret)
	start1 := 49
	for i := 0; i < KeyLength; i++ {
		want := seed[start1+i] ^ secret[i]
		if key1[i] != want {
			t.Errorf("key1[%d] = %d, want %d", i, key1[i], want)
		}
	}
}

func TestApplyRoundTrip(t *testing.T) {
	// Test that apply with encrypt then decrypt recovers the original.
	key := [KeyLength]byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160}
	original := []byte("Hello, World! This is a test of the XTEA cipher for the challenge codec.")
	// Pad to whole blocks.
	padded := make([]byte, ((len(original)+BlockLength-1)/BlockLength)*BlockLength)
	copy(padded, original)

	data := make([]byte, len(padded))
	copy(data, padded)

	apply(data, key, EncryptBlock)
	apply(data, key, DecryptBlock)

	for i := range padded {
		if data[i] != padded[i] {
			t.Errorf("byte %d: got %d, want %d", i, data[i], padded[i])
		}
	}
}

func TestRSAWrapSeed(t *testing.T) {
	// Test that WrapSeed produces SeedLength bytes.
	// Use a modulus that is exactly SeedLength bytes wide (1024 bits).
	modulus := new(big.Int).Lsh(big.NewInt(1), 1023) // 2^1023, which is 128 bytes
	seed := [SeedLength]byte{}
	seed[0] = SeedMarker
	for i := 1; i < SeedLength; i++ {
		seed[i] = byte(i)
	}

	wrapped := WrapSeed(seed, modulus)
	if len(wrapped) != SeedLength {
		t.Fatalf("wrapped length = %d, want %d", len(wrapped), SeedLength)
	}

	// Verify that we can decrypt it back (textbook RSA: decrypt with d = modular inverse).
	// Since we don't have d, just verify the output is not the same as the input
	// (encryption should change the value).
	same := true
	for i := range seed {
		if wrapped[i] != seed[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("WrapSeed should produce different output from input")
	}
}

func TestRSAPadLength(t *testing.T) {
	// Test that RSA pads to SeedLength even for small results.
	modulus := big.NewInt(255) // Small modulus, small result
	block := make([]byte, SeedLength)
	block[SeedLength-1] = 2 // Small value

	result := RSA(block, big.NewInt(PublicExponent), modulus)
	// The result should be 2^65537 mod 255 = some small number, but padded.
	// Just verify the length is correct.
	if len(result) != SeedLength {
		t.Errorf("result length = %d, want %d", len(result), SeedLength)
	}
}
