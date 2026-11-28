// Package transport - response decompression.
//
// Go's standard http.Transport only handles gzip and deflate automatically
// (and only when DisableCompression is false). Cloudflare responses are
// often Brotli-compressed (Content-Encoding: br) or zstd-compressed.
//
// This file provides a RoundTripper wrapper that decompresses gzip, deflate,
// and Brotli responses transparently.
package transport

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"

	"github.com/andybalholm/brotli"
)

// decompressTransport wraps an http.RoundTripper and decompresses response
// bodies based on the Content-Encoding header.
type decompressTransport struct {
	base http.RoundTripper
}

// RoundTrip sends the request and decompresses the response body.
func (d *decompressTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := d.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Decompress the body if needed.
	encoding := resp.Header.Get("Content-Encoding")
	if encoding == "" {
		return resp, nil
	}

	// Read the compressed body.
	compressed, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		return resp, err
	}
	resp.Body.Close()

	var decompressed []byte
	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			// Can't decompress — return the original compressed body.
			resp.Body = io.NopCloser(bytes.NewReader(compressed))
			return resp, nil
		}
		decompressed, err = io.ReadAll(reader)
		reader.Close()
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(compressed))
			return resp, nil
		}

	case "deflate":
		reader := flate.NewReader(bytes.NewReader(compressed))
		decompressed, err = io.ReadAll(reader)
		reader.Close()
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(compressed))
			return resp, nil
		}

	case "br":
		reader := brotli.NewReader(bytes.NewReader(compressed))
		decompressed, err = io.ReadAll(reader)
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(compressed))
			return resp, nil
		}

	default:
		// Unknown encoding — return the original body.
		resp.Body = io.NopCloser(bytes.NewReader(compressed))
		return resp, nil
	}

	// Replace the body with the decompressed version.
	resp.Body = io.NopCloser(bytes.NewReader(decompressed))
	resp.ContentLength = int64(len(decompressed))
	resp.Header.Del("Content-Encoding")
	resp.Header.Set("Content-Length", strconv.Itoa(len(decompressed)))

	return resp, nil
}
