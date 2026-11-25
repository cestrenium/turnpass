// Package transport provides the request-based HTTP client used by the
// turnpass solver. It reproduces the relevant browser characteristics using
// uTLS for the TLS ClientHello, supports http/https/socks5/socks5h proxies,
// and integrates the cookies.Jar.
//
// A BrowserClient is constructed once per solve (each solve owns its own
// connections, cookie jar and proxy) and is safe for concurrent use within
// that solve.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"

	"github.com/cestrenium/turnpass/internal/cookies"
	"github.com/cestrenium/turnpass/internal/fingerprint"
)

// BrowserClient is a per-solve HTTP client.
type BrowserClient struct {
	httpClient   *http.Client
	cookieJar    *cookies.Jar
	headers      map[string]string // default headers from the fingerprint
	userAgent    string
	requestOrder map[string][]string
	engine       fingerprint.Engine
	profile      string
	platform     string
}

// Config holds the inputs needed to build a BrowserClient.
type Config struct {
	Fingerprint *fingerprint.Fingerprint
	Proxy       string // optional http://, https://, socks5://, socks5h:// URL
	TrustedRoot []byte // optional PEM bundle to trust instead of system roots
	Timeout     time.Duration
}

// New builds a BrowserClient from the given config.
func New(cfg Config) (*BrowserClient, error) {
	if cfg.Fingerprint == nil {
		return nil, errors.New("transport: fingerprint is required")
	}
	fp := cfg.Fingerprint
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	jar := cookies.New()

	helloID := clientHelloID(fp.Engine, fp.Transport.Profile)

	transport, err := buildTransport(cfg, helloID)
	if err != nil {
		return nil, err
	}

	hc := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		Jar:       netHTTPJarAdapter{jar},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 20 {
				return errors.New("stopped after 20 redirects")
			}
			applyHeaders(req, fp.Transport.Headers)
			return nil
		},
	}

	return &BrowserClient{
		httpClient:   hc,
		cookieJar:    jar,
		headers:      fp.Transport.Headers,
		userAgent:    fp.UserAgent(),
		requestOrder: fp.Transport.Requests.Headers,
		engine:       fp.Engine,
		profile:      fp.Transport.Profile,
		platform:     fp.Transport.Platform,
	}, nil
}

// Jar returns the cookie jar.
func (c *BrowserClient) Jar() *cookies.Jar { return c.cookieJar }

// UserAgent returns the configured User-Agent.
func (c *BrowserClient) UserAgent() string { return c.userAgent }

// Engine returns the browser engine.
func (c *BrowserClient) Engine() fingerprint.Engine { return c.engine }

// SetInsecureTLS configures the transport to accept any TLS certificate.
// This is for testing only (e.g., against httptest.NewTLSServer).
func (c *BrowserClient) SetInsecureTLS() {
	if t, ok := c.httpClient.Transport.(*http.Transport); ok {
		t.TLSClientConfig.InsecureSkipVerify = true
		t.ForceAttemptHTTP2 = false
	}
}

// Do sends req, applying the per-request-kind header order from the
// fingerprint. kind selects which header order to use (e.g. "navigation",
// "iframe", "script", "orchestrator_post", "challenge_post").
//
// For each header in the kind's template:
//   - "name: value" → set as a static header
//   - "name" → look up in extraHeaders; if found, set it; otherwise skip
//     (it's a dynamic header like content-length, origin, referer, cf-chl
//     that the caller must provide)
//
// If the kind has no template, falls back to the default headers.
func (c *BrowserClient) Do(ctx context.Context, kind, method, rawURL string, body io.Reader, extraHeaders map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	// Try per-kind header template first.
	template, hasTemplate := c.requestOrder[kind]
	if hasTemplate {
		// Apply headers in the template order.
		for _, hdr := range template {
			if idx := strings.Index(hdr, ":"); idx >= 0 {
				// Static header: "name: value"
				name := strings.TrimSpace(hdr[:idx])
				value := strings.TrimSpace(hdr[idx+1:])
				req.Header.Set(name, value)
			} else {
				// Dynamic header: "name" — look up in extraHeaders.
				if v, ok := extraHeaders[hdr]; ok {
					req.Header.Set(hdr, v)
				}
				// Also try case-insensitive lookup.
				for ek, ev := range extraHeaders {
					if strings.EqualFold(ek, hdr) {
						req.Header.Set(hdr, ev)
						break
					}
				}
			}
		}
		// Also apply any extra headers not in the template.
		for k, v := range extraHeaders {
			if req.Header.Get(k) == "" {
				req.Header.Set(k, v)
			}
		}
	} else {
		// Fall back to default headers.
		applyHeaders(req, c.headers)
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
	}

	if c.userAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	return c.httpClient.Do(req)
}

// Get performs a GET with the given request kind.
func (c *BrowserClient) Get(ctx context.Context, kind, rawURL string) (*http.Response, error) {
	return c.Do(ctx, kind, http.MethodGet, rawURL, nil, nil)
}

// Post performs a POST with the given request kind and body.
func (c *BrowserClient) Post(ctx context.Context, kind, rawURL, contentType string, body io.Reader) (*http.Response, error) {
	return c.Do(ctx, kind, http.MethodPost, rawURL, body, map[string]string{"Content-Type": contentType})
}

// AddCookie parses a Set-Cookie header value against the given URL.
func (c *BrowserClient) AddCookie(u *url.URL, setCookie string) {
	c.cookieJar.SetCookie(u, setCookie)
}

func applyHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

func clientHelloID(engine fingerprint.Engine, profile string) utls.ClientHelloID {
	switch engine {
	case fingerprint.EngineWebKit:
		return utls.HelloIOS_Auto
	case fingerprint.EngineChromium:
		return utls.HelloChrome_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

func buildTransport(cfg Config, helloID utls.ClientHelloID) (*http.Transport, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

	// Build the proxy URL if any.
	var proxyURL *url.URL
	var err error
	if cfg.Proxy != "" {
		proxyURL, err = url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("transport: invalid proxy URL: %w", err)
		}
	}

	// Build the TLS config for verification (uTLS does the actual handshake).
	tlsConfig := &tls.Config{}
	if len(cfg.TrustedRoot) > 0 {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(cfg.TrustedRoot) {
			return nil, errors.New("transport: failed to parse trusted_root PEM")
		}
		tlsConfig.RootCAs = roots
	}

	t := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true, // we control Accept-Encoding ourselves
	}

	// uTLS dialer for the TLS layer. We wrap the inner dialer so that proxies
	// are honoured: if a proxy is set, we connect to the proxy first, then run
	// the uTLS handshake over that connection.
	innerDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	if proxyURL != nil {
		pd, err := buildProxyDialer(proxyURL)
		if err != nil {
			return nil, err
		}
		innerDial = pd.DialContext
	}

	t.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := innerDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(addr)
		uConn := utls.UClient(conn, &utls.Config{ServerName: host, InsecureSkipVerify: tlsConfig.InsecureSkipVerify, RootCAs: tlsConfig.RootCAs}, helloID)
		if err := uConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("uTLS handshake: %w", err)
		}
		// Wrap the uTLS connection so Go's http.Transport can detect HTTP/2
		// via ALPN. The transport checks for *tls.Conn or a ConnectionStater
		// interface; utls.UConn satisfies neither, so we wrap it.
		return &utlsConnWrapper{uConn: uConn}, nil
	}

	// For non-TLS (plain HTTP) requests, honour the proxy too.
	if proxyURL != nil {
		t.Proxy = http.ProxyURL(proxyURL)
	}

	// Go's built-in HTTP/2 support (enabled by ForceAttemptHTTP2 above)
	// detects HTTP/2 by checking the ALPN protocol on the TLS connection.
	// Our utlsConnWrapper implements ConnectionState() tls.ConnectionState
	// which the transport uses for this check. No explicit http2.ConfigureTransport
	// is needed; the built-in support handles it.

	return t, nil
}

func buildProxyDialer(proxyURL *url.URL) (proxy.ContextDialer, error) {
	scheme := strings.ToLower(proxyURL.Scheme)
	switch scheme {
	case "socks5", "socks5h":
		auth := &proxy.Auth{}
		if proxyURL.User != nil {
			auth.User = proxyURL.User.Username()
			pw, ok := proxyURL.User.Password()
			if ok {
				auth.Password = pw
			}
		}
		d, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("transport: socks5 dialer: %w", err)
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("transport: socks5 dialer does not implement ContextDialer")
		}
		return cd, nil
	case "http", "https":
		return newHTTPProxyDialer(proxyURL), nil
	default:
		return nil, fmt.Errorf("transport: unsupported proxy scheme %q", scheme)
	}
}

// httpProxyDialer dials through an HTTP CONNECT proxy.
type httpProxyDialer struct {
	proxyURL *url.URL
}

func newHTTPProxyDialer(u *url.URL) *httpProxyDialer { return &httpProxyDialer{proxyURL: u} }

func (d *httpProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *httpProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	_ = network
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", d.proxyURL.Host)
	if err != nil {
		return nil, err
	}
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if d.proxyURL.User != nil {
		connectReq += "Proxy-Authorization: Basic " + basicAuth(d.proxyURL.User.Username(), passwordOrEmpty(d.proxyURL)) + "\r\n"
	}
	connectReq += "\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufioReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}
	return conn, nil
}

func passwordOrEmpty(u *url.URL) string {
	p, ok := u.User.Password()
	if !ok {
		return ""
	}
	return p
}

// netHTTPJarAdapter adapts our cookies.Jar to net/http.CookieJar so that
// http.Client follows redirects and stores Set-Cookie headers automatically.
type netHTTPJarAdapter struct{ inner *cookies.Jar }

func (a netHTTPJarAdapter) SetCookies(u *url.URL, cks []*http.Cookie) {
	for _, c := range cks {
		a.inner.SetCookie(u, c.String())
	}
}

func (a netHTTPJarAdapter) Cookies(u *url.URL) []*http.Cookie {
	stored := a.inner.Cookies(u)
	out := make([]*http.Cookie, 0, len(stored))
	for _, c := range stored {
		out = append(out, &http.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Secure: c.Secure, HttpOnly: c.HttpOnly,
		})
	}
	return out
}

// ResponseSummary is a trimmed view of an HTTP response used by the solver
// and the FlareSolverr API.
type ResponseSummary struct {
	Status  int
	URL     string
	Headers http.Header
	Body    []byte
}

// ReadBody reads and closes the response body, returning the bytes.
func ReadBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// ContentLength returns the value of the Content-Length header, or -1.
func ContentLength(h http.Header) int64 {
	v := h.Get("Content-Length")
	if v == "" {
		return -1
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return -1
	}
	return n
}
