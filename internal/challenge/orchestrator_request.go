package challenge

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ExtractOrchestratorRequest extracts the POST URL and cf-chl token from a
// deobfuscated orchestrator script. The orchestrator's POST URL is built
// from _cf_chl_opt properties, and the cf-chl token is another property.
//
// In the deobfuscated source, we can find:
// 1. setRequestHeader(`cf-chl`, _cf_chl_opt.PROPERTY) -> the cf-chl token
// 2. String concatenation producing /cdn-cgi/challenge-platform/h/VARIANT/fo/RAY:TIMESTAMP:TOKEN/
//
// The _cf_chl_opt properties are renamed at orchestrator startup, but the
// values come from the challenge page HTML which uses standard names:
// cH = cf-chl token
// cFPWv = variant (e.g. "b")
// cRay = ray
// cUPMDTk = answered URL
func ExtractOrchestratorRequest(deobfuscatedSource, pageURL string) (*InitialRequest, error) {
	// Extract _cf_chl_opt values from the challenge page HTML.
	// We need to find the cf-chl token and the POST path components.

	// Find the /fo/ path in the orchestrator.
	// Pattern: /fo/TIMESTAMP:TIMESTAMP:TOKEN/
	rxFoPath := regexp.MustCompile("`/fo/([0-9]+:[0-9]+:[A-Za-z0-9_-]+)/`")
	foMatch := rxFoPath.FindStringSubmatch(deobfuscatedSource)
	var foPath string
	if len(foMatch) >= 2 {
		foPath = "/fo/" + foMatch[1] + "/"
	}

	// Find the cf-chl token from the challenge page.
	// In the orchestrator: setRequestHeader(`cf-chl`, _cf_chl_opt.PROPERTY)
	// The PROPERTY value is the cf-chl token, which is set in the challenge
	// page HTML as _cf_chl_opt.cH = 'token'.
	// We can extract cH from the challenge page HTML directly.

	// Parse the challenge page URL to get the origin.
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("parsing page URL: %w", err)
	}
	origin := parsedURL.Scheme + "://" + parsedURL.Host

	// The POST URL is: origin + /cdn-cgi/challenge-platform/h/ + VARIANT + /fo/ + RAY:TIMESTAMP:TOKEN/
	// We need the variant and ray from _cf_chl_opt.

	// Extract variant from the orchestrator source.
	// In the deobfuscated source, the variant is concatenated with the path.
	// Pattern: `/cdn-cgi/challenge-platform/h/` + VARIANT_PROPERTY + `/fo/...`
	// The variant is a single lowercase letter like "b" or "g".

	// Try to find the variant in _cf_chl_opt.cFPWv
	// In the orchestrator, cFPWv is accessed via an obfuscated property name.
	// But we can look for the /h/ pattern to find the variant.
	rxVariant := regexp.MustCompile("`/cdn-cgi/challenge-platform/h/`\\)\\+[^,]+")
	_ = rxVariant.FindString(deobfuscatedSource)

	// Actually, let's look for the full POST URL pattern in the source.
	// The POST URL is built as a string concatenation.
	// We can find it by looking for /fo/ paths.
	rxPostURL := regexp.MustCompile("`/cdn-cgi/challenge-platform/h/`\\)\\+\\S+\\.\\w+\\+\\(`(/fo/[^`]+)`")
	postMatch := rxPostURL.FindStringSubmatch(deobfuscatedSource)
	if len(postMatch) >= 2 {
		foPath = postMatch[1]
	}

	// Find the /eb/ path (the orchestrator's endpoint, not /fo/).
	// /eb/ is the orchestrator POST path.
	rxEbPath := regexp.MustCompile("`(/eb/[0-9]+:[0-9]+:[A-Za-z0-9_-]+/?)`")
	ebMatch := rxEbPath.FindStringSubmatch(deobfuscatedSource)
	if len(ebMatch) >= 2 {
		// The POST URL uses /eb/ for the orchestrator.
		// Full URL: origin + /cdn-cgi/challenge-platform/h/ + variant + /eb/ + ...
		_ = ebMatch
	}

	// For now, extract what we can and return a partial result.
	// The caller will need to fill in the variant and ray from the
	// challenge page's _cf_chl_opt.
	req := &InitialRequest{
		Options: make(map[string]string),
	}
	req.Options["foPath"] = foPath

	// Try to find the cf-chl token property name.
	// Pattern: setRequestHeader(`cf-chl`, SOMETHING.PROPERTY)
	rxCfChl := regexp.MustCompile("`cf-chl`\\),\\s*\\S+\\[\\S+\\]\\.(\\w+)")
	cfChlMatch := rxCfChl.FindStringSubmatch(deobfuscatedSource)
	if len(cfChlMatch) >= 2 {
		req.Options["cfChlProperty"] = cfChlMatch[1]
	}

	// Try to find the variant property name.
	// Pattern: `/cdn-cgi/challenge-platform/h/`)+SOMETHING.PROPERTY
	rxVariantProp := regexp.MustCompile("`/cdn-cgi/challenge-platform/h/`\\)\\+\\S+\\.(\\w+)")
	variantPropMatch := rxVariantProp.FindStringSubmatch(deobfuscatedSource)
	if len(variantPropMatch) >= 2 {
		req.Options["variantProperty"] = variantPropMatch[1]
	}

	// Build the POST URL if we have enough info.
	// The variant and ray come from _cf_chl_opt in the challenge page HTML.
	// cFPWv = variant, cRay = ray
	// These are set by the challenge page, not the orchestrator.
	if foPath != "" {
		req.URL = origin + "/cdn-cgi/challenge-platform/h/" + foPath
	}

	return req, nil
}

// ExtractCfChlOptValues extracts ALL _cf_chl_opt values from the
// challenge page HTML. These include standard names (cH, cFPWv, cRay,
// cUPMDTk, cITimeS) and additional values (cType, cN, cTplC, cTplO,
// cTplV, cvId, cZone, fa, md, mdrd). All are used to build the payload.
func ExtractCfChlOptValues(html string) map[string]string {
	values := make(map[string]string)

	// Extract ALL key:value pairs from the _cf_chl_opt object.
	// Pattern: key: "value" or key: 'value' or key: number
	rx := regexp.MustCompile(`(\w+)\s*:\s*['"]([^'"]+)['"]`)
	for _, m := range rx.FindAllStringSubmatch(html, -1) {
		// Only keep keys that look like _cf_chl_opt properties.
		// The _cf_chl_opt object has short keys like cH, cFPWv, etc.
		key := m[1]
		val := m[2]
		if len(key) <= 10 && len(val) > 0 {
			values[key] = val
		}
	}

	// Also extract numeric values (cTplC:0, cTplO:0, cTplV:5, cvId:3)
	rxNum := regexp.MustCompile(`(c\w+)\s*:\s*(\d+)`)
	for _, m := range rxNum.FindAllStringSubmatch(html, -1) {
		if _, exists := values[m[1]]; !exists {
			values[m[1]] = m[2]
		}
	}

	return values
}

// BuildOrchestratorPostURL builds the orchestrator POST URL from the
// _cf_chl_opt values and the /fo/ path found in the orchestrator source.
func BuildOrchestratorPostURL(pageURL, variant, ray, foPath string) string {
	parsedURL, _ := url.Parse(pageURL)
	origin := parsedURL.Scheme + "://" + parsedURL.Host
	return origin + "/cdn-cgi/challenge-platform/h/" + variant + foPath + ray + "/"
}

// BuildOrchestratorPostURLOriginal builds the POST URL using the /eb/ pattern.
// The orchestrator uses /eb/ for its initial POST, not /fo/.
func BuildOrchestratorPostURLOriginal(pageURL string, cfChlOpt map[string]string, foPath string) string {
	parsedURL, _ := url.Parse(pageURL)
	origin := parsedURL.Scheme + "://" + parsedURL.Host
	variant := cfChlOpt["cFPWv"]
	if variant == "" {
		variant = "b"
	}
	// The /eb/ path from the orchestrator
	ebPath := strings.Replace(foPath, "/fo/", "/eb/", 1)
	return origin + "/cdn-cgi/challenge-platform/h/" + variant + ebPath
}
