package solver

import (
	"github.com/cestrenium/turnpass/internal/fingerprint"
	"github.com/cestrenium/turnpass/internal/transport"
)

// newTestClient builds a BrowserClient for testing. The transport's TLS config
// is set to accept any certificate (for httptest.NewServer).
func newTestClient(fp *fingerprint.Fingerprint) (*transport.BrowserClient, error) {
	client, err := transport.New(transport.Config{Fingerprint: fp})
	if err != nil {
		return nil, err
	}
	// Override for test server.
	client.SetInsecureTLS()
	return client, nil
}
