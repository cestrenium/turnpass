package challenge

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// InitialRequest holds the POST destination and session token extracted from
// the iframe's bootstrap JavaScript.
type InitialRequest struct {
	// URL is the POST URL for challenge payloads, extracted from the inline
	// JavaScript. It is a /cdn-cgi/challenge-platform/.../fo/... path.
	URL string
	// CfChl is the token carried in the cf-chl header, extracted from
	// setRequestHeader('cf-chl', <token>) calls.
	CfChl string
	// Ray is the ray identifier extracted from the POST URL path.
	Ray string
	// Options is the _cf_chl_opt object's key-value pairs.
	Options map[string]string
}

var (
	// Matches /cdn-cgi/challenge-platform/.../fo/... paths in string literals.
	rxPostPath = regexp.MustCompile(`['"](/cdn-cgi/challenge-platform/[^'"]*/fo/[^'"]*)['"]`)
	// Matches setRequestHeader('cf-chl', <token>) or setRequestHeader("cf-chl", <token>).
	rxCfChlHeader = regexp.MustCompile(`(?i)setRequestHeader\s*\(\s*['"]cf-chl['"]\s*,\s*['"]([^'"]*)['"]\s*\)`)
)

// ExtractInitialRequest parses the inline JavaScript from a Turnstile iframe
// and extracts the POST URL, cf-chl token, and ray.
//
// The POST URL is a /cdn-cgi/challenge-platform/.../fo/... path. The cf-chl
// token is the argument to setRequestHeader('cf-chl', <token>). The ray is
// extracted from the POST URL path: /fo/<build>/<ray>/<token>.
//
// iframeURL is used to resolve relative paths.
func ExtractInitialRequest(inlineJS, iframeURL string) (*InitialRequest, error) {
	// Extract _cf_chl_opt options.
	options := extractCfChlOpt(inlineJS)

	// Find all POST paths.
	postPaths := rxPostPath.FindStringSubmatch(inlineJS)
	var postPath string
	if len(postPaths) >= 2 {
		postPath = postPaths[1]
	}

	// Find the cf-chl token.
	var cfChl string
	if m := rxCfChlHeader.FindStringSubmatch(inlineJS); len(m) >= 2 {
		cfChl = m[1]
	}

	// If we have a path but no token, try to extract the token from the path.
	// The path format is /cdn-cgi/challenge-platform/h/<variant>/fo/<build>/<ray>/<token>
	if cfChl == "" && postPath != "" {
		parts := strings.Split(postPath, "/")
		if len(parts) > 0 {
			cfChl = parts[len(parts)-1]
		}
	}

	// If we have a token but no matching path, try to find a path ending with the token.
	if postPath == "" && cfChl != "" {
		// Look for any challenge-platform path that ends with the token.
		allPaths := rxPostPath.FindAllStringSubmatch(inlineJS, -1)
		for _, m := range allPaths {
			if strings.HasSuffix(m[1], "/"+cfChl) {
				postPath = m[1]
				break
			}
		}
	}

	if postPath == "" {
		return nil, fmt.Errorf("no challenge POST URL found in iframe JavaScript")
	}

	// Resolve the POST URL against the iframe URL.
	postURL, err := resolveURL(iframeURL, postPath)
	if err != nil {
		return nil, fmt.Errorf("resolving POST URL: %w", err)
	}

	// Extract the ray from the POST URL.
	ray := extractRay(postPath)

	return &InitialRequest{
		URL:     postURL,
		CfChl:   cfChl,
		Ray:     ray,
		Options: options,
	}, nil
}

// extractRay extracts the ray from a /fo/<build>/<ray>/<token> path.
// Returns empty string if the ray cannot be extracted.
func extractRay(postPath string) string {
	// Split on /fo/ to get the part after it.
	idx := strings.Index(postPath, "/fo/")
	if idx < 0 {
		return ""
	}
	afterFO := postPath[idx+4:]
	// Split by / : <build>/<ray>/<token>
	parts := strings.Split(afterFO, "/")
	if len(parts) < 3 {
		return ""
	}
	return parts[1]
}

// IsPostPath reports whether path is a challenge-platform /fo/ path.
func IsPostPath(path string) bool {
	return strings.HasPrefix(path, "/cdn-cgi/challenge-platform/") && strings.Contains(path, "/fo/")
}

// ParseIframeURL parses an iframe URL and returns its origin.
func ParseIframeURL(iframeURL string) (string, error) {
	parsed, err := url.Parse(iframeURL)
	if err != nil {
		return "", err
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}
