package codec

// XTEA block cipher implementation for the challenge codec.
//
// XTEA encrypts 8-byte blocks using a 128-bit key (four 32-bit words).
// The challenge codec uses 32 rounds (64 half-rounds), matching cfsolve's
// implementation.

// KeyLength is the length of the XTEA key and key-transform secret in bytes.
const KeyLength = 16

// BlockLength is the XTEA block size in bytes.
const BlockLength = 8

// Delta is XTEA's key schedule constant.
const Delta uint32 = 0x9E3779B9

// Schedule produces XTEA's round keys, each with its running sum already
// added. Returns 64 uint32 values (32 rounds × 2 half-rounds).
func schedule(key [4]uint32) [64]uint32 {
	var keys [64]uint32
	sum := uint32(0)
	for round := 0; round < 32; round++ {
		keys[round*2] = sum + key[sum&3]
		sum += Delta
		keys[round*2+1] = sum + key[(sum>>11)&3]
	}
	return keys
}

func mix(value uint32) uint32 {
	return (value<<4 ^ value>>5) + value
}

// EncryptBlock encrypts a single 8-byte block (two uint32 words) using
// the given round keys.
func EncryptBlock(block [2]uint32, keys *[64]uint32) [2]uint32 {
	a, b := block[0], block[1]
	for round := 0; round < 32; round++ {
		a += mix(b) ^ keys[round*2]
		b += mix(a) ^ keys[round*2+1]
	}
	return [2]uint32{a, b}
}

// DecryptBlock decrypts a single 8-byte block (two uint32 words) using
// the given round keys.
func DecryptBlock(block [2]uint32, keys *[64]uint32) [2]uint32 {
	a, b := block[0], block[1]
	for round := 31; round >= 0; round-- {
		b -= mix(a) ^ keys[round*2+1]
		a -= mix(b) ^ keys[round*2]
	}
	return [2]uint32{a, b}
}

// words converts a 16-byte key to four uint32 words (big-endian).
func words16(bytes []byte) [4]uint32 {
	return [4]uint32{
		uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3]),
		uint32(bytes[4])<<24 | uint32(bytes[5])<<16 | uint32(bytes[6])<<8 | uint32(bytes[7]),
		uint32(bytes[8])<<24 | uint32(bytes[9])<<16 | uint32(bytes[10])<<8 | uint32(bytes[11]),
		uint32(bytes[12])<<24 | uint32(bytes[13])<<16 | uint32(bytes[14])<<8 | uint32(bytes[15]),
	}
}

// words2 converts an 8-byte block to two uint32 words (big-endian).
func words2(bytes []byte) [2]uint32 {
	return [2]uint32{
		uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3]),
		uint32(bytes[4])<<24 | uint32(bytes[5])<<16 | uint32(bytes[6])<<8 | uint32(bytes[7]),
	}
}

// apply applies a cipher function to each complete 8-byte block in data.
// Block i uses a key derived by encrypting i and i+1 (mod 256) with the
// original key, then scheduling the result.
func apply(data []byte, key [KeyLength]byte, cipher func([2]uint32, *[64]uint32) [2]uint32) {
	base := schedule(words16(key[:]))
	numBlocks := len(data) / BlockLength

	// Pre-compute schedules for all 256 possible block indices.
	var schedules [256][64]uint32
	for i := 0; i < 256 && i < numBlocks; i++ {
		a := EncryptBlock([2]uint32{0, uint32(i)}, &base)
		b := EncryptBlock([2]uint32{0, uint32(i + 1)}, &base)
		schedules[i] = schedule([4]uint32{a[0], a[1], b[0], b[1]})
	}

	for i := 0; i < numBlocks; i++ {
		offset := i * BlockLength
		block := words2(data[offset : offset+BlockLength])
		keys := &schedules[i%256]
		result := cipher(block, keys)
		data[offset] = byte(result[0] >> 24)
		data[offset+1] = byte(result[0] >> 16)
		data[offset+2] = byte(result[0] >> 8)
		data[offset+3] = byte(result[0])
		data[offset+4] = byte(result[1] >> 24)
		data[offset+5] = byte(result[1] >> 16)
		data[offset+6] = byte(result[1] >> 8)
		data[offset+7] = byte(result[1])
	}
}

// FrameKey derives the XTEA key from a seed window selected by padding,
// masked with the session's key-transform secret.
func FrameKey(seed []byte, padding byte, secret [KeyLength]byte) [KeyLength]byte {
	start := 40 + 9*int(padding)
	var key [KeyLength]byte
	for i := 0; i < KeyLength; i++ {
		key[i] = seed[start+i] ^ secret[i]
	}
	return key
}
