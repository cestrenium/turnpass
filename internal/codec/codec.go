package codec

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
)

// Codec holds the session-specific codec parameters: the base64 alphabet,
// RSA modulus, and key-transform secret.
type Codec struct {
	alphabet *base64.Encoding
	modulus  *big.Int
	secret   [KeyLength]byte
}

// NewCodec creates a Codec from the session's alphabet (64 distinct printable
// ASCII characters), RSA modulus (exactly SeedLength bytes wide), and
// key-transform secret.
func NewCodec(alphabet string, modulus *big.Int, secret [KeyLength]byte) (*Codec, error) {
	if len(alphabet) != 64 {
		return nil, fmt.Errorf("alphabet must be 64 characters, got %d", len(alphabet))
	}
	// Verify the modulus is exactly SeedLength bytes wide.
	modulusBytes := modulus.BitLen()
	if modulusBytes == 0 || (modulusBytes+7)/8 != SeedLength {
		return nil, fmt.Errorf("RSA modulus must be %d bytes wide, got %d bits", SeedLength, modulusBytes)
	}

	// Create a base64 encoding with the custom alphabet, no padding on encode,
	// and lenient padding on decode (matching cfsolve's engine).
	enc := base64.NewEncoding(alphabet).WithPadding(base64.NoPadding)

	return &Codec{
		alphabet: enc,
		modulus:  modulus,
		secret:   secret,
	}, nil
}

// Encode encodes a JSON payload into the challenge POST format:
// 1. Frame the payload (marker + compression flag + space-wrapped JSON).
// 2. Pad to whole 8-byte blocks.
// 3. Generate a random 128-byte seed, fix the first byte to SeedMarker.
// 4. Derive the XTEA key from the seed, padding, and secret.
// 5. Encrypt the frame with XTEA.
// 6. RSA-encrypt the seed.
// 7. Base64-encode the envelope: wrapped_seed + padding_byte + encrypted_frame.
func (c *Codec) Encode(jsonPayload []byte) (string, error) {
	// Frame the payload.
	frame, err := Frame(jsonPayload)
	if err != nil {
		return "", fmt.Errorf("framing payload: %w", err)
	}

	// Pad to whole blocks.
	blockLen := (len(frame) + BlockLength - 1) / BlockLength * BlockLength
	padding := byte(blockLen - len(frame))
	padded := make([]byte, blockLen)
	copy(padded, frame)

	// Generate a random seed.
	var seed [SeedLength]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return "", fmt.Errorf("generating seed: %w", err)
	}
	seed[0] = SeedMarker

	// Derive the XTEA key and encrypt the frame.
	key := FrameKey(seed[:], padding, c.secret)
	apply(padded, key, EncryptBlock)

	// RSA-encrypt the seed.
	wrappedSeed := WrapSeed(seed, c.modulus)

	// Build the envelope: wrapped_seed + padding_byte + encrypted_frame.
	envelope := make([]byte, 0, SeedLength+1+len(padded))
	envelope = append(envelope, wrappedSeed[:]...)
	envelope = append(envelope, padding)
	envelope = append(envelope, padded...)

	// Base64-encode the envelope.
	return c.alphabet.EncodeToString(envelope), nil
}

// Decode reverses Encode: base64-decode the envelope, split into wrapped seed,
// padding byte, and encrypted frame; RSA-decrypt the seed (requires the
// private key, which we don't have for the server's sessions); derive the XTEA
// key; decrypt the frame; unframe the payload.
//
// Note: This function is for testing and for sessions where we hold the RSA
// private key. In practice, the server holds the private key and we only
// encode (not decode) request payloads.
func (c *Codec) Decode(encoded string, seed [SeedLength]byte) ([]byte, error) {
	// Base64-decode the envelope.
	envelope, err := c.alphabet.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding the POST envelope: %w", err)
	}

	// Split into wrapped seed, padding byte, and frame.
	if len(envelope) < SeedLength+1 {
		return nil, fmt.Errorf("the POST envelope is shorter than a wrapped seed")
	}
	padding := envelope[SeedLength]
	frame := envelope[SeedLength+1:]

	if len(frame)%BlockLength != 0 {
		return nil, fmt.Errorf("the POST frame is not whole blocks: %d bytes", len(frame))
	}
	if int(padding) >= BlockLength {
		return nil, fmt.Errorf("the padding byte is not below a block: %d", padding)
	}

	// Derive the XTEA key and decrypt the frame.
	key := FrameKey(seed[:], padding, c.secret)
	apply(frame, key, DecryptBlock)

	// Unframe the payload.
	return Unframe(frame, padding)
}
