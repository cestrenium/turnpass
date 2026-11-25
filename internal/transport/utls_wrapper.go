package transport

import (
	"crypto/tls"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// utlsConnWrapper wraps a utls.UConn and exposes a ConnectionState method
// returning a standard tls.ConnectionState. This allows Go's http.Transport
// to detect the ALPN-negotiated protocol (h2 or http/1.1) and use HTTP/2
// when the server supports it.
//
// Without this wrapper, http.Transport cannot detect HTTP/2 because it
// type-asserts the TLS connection to *tls.Conn, which utls.UConn is not.
type utlsConnWrapper struct {
	uConn *utls.UConn
}

func (w *utlsConnWrapper) Read(b []byte) (int, error)         { return w.uConn.Read(b) }
func (w *utlsConnWrapper) Write(b []byte) (int, error)        { return w.uConn.Write(b) }
func (w *utlsConnWrapper) Close() error                       { return w.uConn.Close() }
func (w *utlsConnWrapper) LocalAddr() net.Addr                { return w.uConn.LocalAddr() }
func (w *utlsConnWrapper) RemoteAddr() net.Addr               { return w.uConn.RemoteAddr() }
func (w *utlsConnWrapper) SetDeadline(t time.Time) error      { return w.uConn.SetDeadline(t) }
func (w *utlsConnWrapper) SetReadDeadline(t time.Time) error  { return w.uConn.SetReadDeadline(t) }
func (w *utlsConnWrapper) SetWriteDeadline(t time.Time) error { return w.uConn.SetWriteDeadline(t) }

// ConnectionState returns a standard tls.ConnectionState so that
// http.Transport can read the NegotiatedProtocol (ALPN) and detect HTTP/2.
func (w *utlsConnWrapper) ConnectionState() tls.ConnectionState {
	state := w.uConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}
