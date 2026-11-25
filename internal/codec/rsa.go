package codec

import (
	"fmt"
	"math/big"
)

// SeedLength is the length of the random seed and the RSA-encrypted seed in bytes.
const SeedLength = 128

// SeedMarker is the first byte of the seed, fixed to keep the seed below the modulus.
const SeedMarker byte = 2

// PublicExponent is the RSA public exponent used to encrypt seeds.
const PublicExponent = 65537

// WrapSeed encrypts seed with modulus using textbook RSA.
// Returns the encrypted seed as big-endian bytes, left-padded to SeedLength.
func WrapSeed(seed [SeedLength]byte, modulus *big.Int) [SeedLength]byte {
	return RSA(seed[:], big.NewInt(PublicExponent), modulus)
}

// RSA computes block^exponent mod modulus as big-endian bytes, left-padded
// to SeedLength.
func RSA(block []byte, exponent, modulus *big.Int) [SeedLength]byte {
	value := new(big.Int).SetBytes(block)
	result := new(big.Int).Exp(value, exponent, modulus)
	bytes := result.Bytes()

	var padded [SeedLength]byte
	if len(bytes) > SeedLength {
		panic(fmt.Sprintf("RSA result too long: %d bytes", len(bytes)))
	}
	copy(padded[SeedLength-len(bytes):], bytes)
	return padded
}
