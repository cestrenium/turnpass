// Package cookies implements an in-memory cookie jar that matches the
// semantics cfsolve needs: domain (exact or subdomain) and path (RFC 6265)
// matching, Secure/HttpOnly/SameSite awareness, and Set-Cookie parsing.
//
// The jar is safe for concurrent use.
package cookies

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Cookie mirrors net/http.Cookie but is easier to serialise for the
// FlareSolverr session store.
type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain,omitempty"`
	Path     string    `json:"path,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
	Secure   bool      `json:"secure,omitempty"`
	HttpOnly bool      `json:"http_only,omitempty"`
	SameSite string    `json:"same_site,omitempty"`
}

// Jar is a thread-safe in-memory cookie jar.
type Jar struct {
	mu   sync.RWMutex
	data map[string][]*Cookie // keyed by lowercased domain
}

// New returns an empty cookie jar.
func New() *Jar { return &Jar{data: make(map[string][]*Cookie)} }

// SetCookie parses a Set-Cookie header value and stores it for the given URL.
func (j *Jar) SetCookie(u *url.URL, raw string) {
	if raw == "" {
		return
	}
	h := http.Header{}
	h.Add("Set-Cookie", raw)
	resp := http.Response{Header: h}
	cookies := resp.Cookies()
	for _, c := range cookies {
		stored := &Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  c.Expires,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
			SameSite: sameSiteString(c.SameSite),
		}
		if stored.Domain == "" {
			stored.Domain = u.Hostname()
		}
		if stored.Path == "" {
			stored.Path = defaultPath(u.Path)
		}
		j.store(stored)
	}
}

// SetCookies applies many Set-Cookie headers at once.
func (j *Jar) SetCookies(u *url.URL, raws []string) {
	for _, raw := range raws {
		j.SetCookie(u, raw)
	}
}

func (j *Jar) store(c *Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	domain := strings.ToLower(c.Domain)
	list := j.data[domain]
	// Replace any existing cookie with the same name+path.
	kept := list[:0]
	for _, existing := range list {
		if existing.Name == c.Name && existing.Path == c.Path {
			continue
		}
		kept = append(kept, existing)
	}
	kept = append(kept, c)
	j.data[domain] = kept
}

// Cookies returns all cookies matching the URL, in the order a browser would
// send them (longest path first, then insertion order).
func (j *Jar) Cookies(u *url.URL) []*Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()
	host := u.Hostname()
	var out []*Cookie
	now := time.Now()
	for domain, list := range j.data {
		if !domainMatches(host, domain) {
			continue
		}
		for _, c := range list {
			if !c.Expires.IsZero() && c.Expires.Before(now) {
				continue
			}
			if c.Secure && u.Scheme != "https" && u.Scheme != "wss" {
				continue
			}
			if !pathMatches(u.Path, c.Path) {
				continue
			}
			out = append(out, c)
		}
	}
	sortCookies(out)
	return out
}

// CookieHeader returns a "name=value; name2=value2" Cookie header value.
func (j *Jar) CookieHeader(u *url.URL) string {
	cs := j.Cookies(u)
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// All returns a snapshot of every stored cookie (for session serialisation).
func (j *Jar) All() []*Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()
	var out []*Cookie
	for _, list := range j.data {
		out = append(out, list...)
	}
	return out
}

// Clear removes all cookies.
func (j *Jar) Clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.data = make(map[string][]*Cookie)
}

// Len returns the number of stored cookies (including expired).
func (j *Jar) Len() int {
	j.mu.RLock()
	defer j.mu.RUnlock()
	n := 0
	for _, list := range j.data {
		n += len(list)
	}
	return n
}

// domainMatches reports whether host should receive cookies set for domain.
// Domain may start with a dot for host-only=false cookies.
func domainMatches(host, domain string) bool {
	host = strings.ToLower(host)
	domain = strings.ToLower(domain)
	if strings.HasPrefix(domain, ".") {
		domain = domain[1:]
	}
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

// pathMatches implements RFC 6265 section 5.1.4 path matching.
func pathMatches(requestPath, cookiePath string) bool {
	if requestPath == cookiePath {
		return true
	}
	if strings.HasPrefix(requestPath, cookiePath) {
		if strings.HasSuffix(cookiePath, "/") {
			return true
		}
		if len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/' {
			return true
		}
	}
	return false
}

// defaultPath implements RFC 6265 section 5.1.4 default-path.
func defaultPath(uriPath string) string {
	if uriPath == "" || uriPath[0] != '/' {
		return "/"
	}
	idx := strings.LastIndex(uriPath[1:], "/")
	if idx < 0 {
		return "/"
	}
	return uriPath[:idx+1]
}

func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

// sortCookies sorts cookies longest-path-first, then by insertion order.
// This is a simple insertion sort; cookie lists per domain are small.
func sortCookies(cs []*Cookie) {
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0 && len(cs[j].Path) > len(cs[j-1].Path); j-- {
			cs[j], cs[j-1] = cs[j-1], cs[j]
		}
	}
}
