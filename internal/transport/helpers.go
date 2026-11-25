package transport

import (
	"bufio"
	"encoding/base64"
)

// bufioReader returns a bufio.Reader over conn. Defined separately so the
// http proxy dialer can use it.
func bufioReader(r interface{ Read([]byte) (int, error) }) *bufio.Reader {
	return bufio.NewReader(r)
}

// basicAuth returns the base64-encoded "user:pass" string for HTTP Basic auth.
func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}
