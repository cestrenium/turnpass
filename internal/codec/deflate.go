package codec

import (
	"bytes"
	"compress/flate"
	"io"
)

// FrameMarker is the frame's leading marker bytes: fd 01.
var FrameMarker = [2]byte{0xfd, 1}

// CompressionThreshold is the minimum payload size for compression to be
// considered. Payloads shorter than this are never compressed.
const CompressionThreshold = 128

// Deflate compresses input using raw DEFLATE (no zlib header) with a single
// final block using fixed Huffman codes. This matches cfsolve's deflate()
// function, which produces output compatible with Go's flate decompressor.
func Deflate(input []byte) ([]byte, error) {
	var buf bytes.Buffer
	// Use flate.DefaultCompression with a fixed Huffman table. Go's flate
	// writer produces valid DEFLATE output that cfsolve's inflater can read.
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(input); err != nil {
		w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Inflate decompresses raw DEFLATE data (no zlib header).
func Inflate(input []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(input))
	defer r.Close()
	return io.ReadAll(r)
}

// Frame builds a frame containing the fd 01 marker, a compression flag, and
// the (optionally compressed) serialized payload.
//
// The payload is space-wrapped JSON: " {json} ". If the JSON is at least
// CompressionThreshold bytes, it is compressed with DEFLATE; compression is
// used only if it reduces the size.
func Frame(jsonPayload []byte) ([]byte, error) {
	// Space-wrap the JSON.
	wrapped := make([]byte, 0, len(jsonPayload)+2)
	wrapped = append(wrapped, ' ')
	wrapped = append(wrapped, jsonPayload...)
	wrapped = append(wrapped, ' ')

	if len(wrapped) >= CompressionThreshold {
		compressed, err := Deflate(wrapped)
		if err != nil {
			return nil, err
		}
		if len(compressed) < len(wrapped) {
			// Use compressed: marker + flag=1 + compressed data.
			result := make([]byte, 0, len(FrameMarker)+1+len(compressed))
			result = append(result, FrameMarker[:]...)
			result = append(result, 1)
			result = append(result, compressed...)
			return result, nil
		}
	}

	// Use uncompressed: marker + flag=0 + raw data.
	result := make([]byte, 0, len(FrameMarker)+1+len(wrapped))
	result = append(result, FrameMarker[:]...)
	result = append(result, 0)
	result = append(result, wrapped...)
	return result, nil
}

// Unframe reverses Frame: removes the marker, checks the compression flag,
// inflates if needed, and strips the space wrapping from the JSON payload.
func Unframe(frame []byte, padding byte) ([]byte, error) {
	// Remove padding zero bytes from the end.
	if int(padding) >= len(frame) {
		return nil, errPaddingOverruns
	}
	unpadded := frame[:len(frame)-int(padding)]

	// Verify padding bytes are zero.
	for _, b := range frame[len(frame)-int(padding):] {
		if b != 0 {
			return nil, errPaddingNotZero
		}
	}

	// Check for the frame marker.
	if len(unpadded) < len(FrameMarker)+1 {
		return nil, errFrameTooShort
	}
	if unpadded[0] != FrameMarker[0] || unpadded[1] != FrameMarker[1] {
		return nil, errNoMarker
	}

	flag := unpadded[2]
	payload := unpadded[3:]

	var jsonBytes []byte
	var err error
	switch flag {
	case 0:
		jsonBytes = payload
	case 1:
		jsonBytes, err = Inflate(payload)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errBadCompressionFlag
	}

	// Strip space wrapping: leading and trailing space.
	if len(jsonBytes) < 2 || jsonBytes[0] != ' ' || jsonBytes[len(jsonBytes)-1] != ' ' {
		return nil, errNotSpaceWrapped
	}
	return jsonBytes[1 : len(jsonBytes)-1], nil
}
