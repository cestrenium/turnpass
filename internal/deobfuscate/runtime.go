package deobfuscate

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/dop251/goja"
)

// EvaluateRuntimeConstants uses the goja JavaScript runtime to execute the
// deobfuscated orchestrator script and extract runtime-computed values.
func EvaluateRuntimeConstants(deobfuscatedSource string) (*RuntimeConstants, error) {
	return EvaluateRuntimeConstantsWithConfig(deobfuscatedSource, nil)
}

// EvaluateRuntimeConstantsWithConfig is like EvaluateRuntimeConstants but
// accepts _cf_chl_opt values from the challenge page to inject into the runtime.
func EvaluateRuntimeConstantsWithConfig(deobfuscatedSource string, cfChlOptValues map[string]string) (*RuntimeConstants, error) {
	vm := goja.New()

	// Set up _cf_chl_opt with values from the challenge page.
	cfChlOpt := make(map[string]interface{})
	for k, v := range cfChlOptValues {
		cfChlOpt[k] = v
	}

	vm.Set("globalThis", map[string]interface{}{})
	vm.Set("self", map[string]interface{}{})
	vm.Set("_cf_chl_opt", cfChlOpt)
	windowObj := map[string]interface{}{
		"_cf_chl_opt": cfChlOpt,
	}
	vm.Set("window", windowObj)

	// Set up navigator
	vm.Set("navigator", map[string]interface{}{
		"hardwareConcurrency": 4,
		"userAgent":           "Mozilla/5.0",
		"platform":            "iPhone",
		"languages":           []string{"en-US"},
	})

	// Set up document
	vm.Set("document", map[string]interface{}{
		"createElement": func(tag string) map[string]interface{} {
			return map[string]interface{}{}
		},
		"getElementsByTagName": func(tag string) []map[string]interface{} {
			return []map[string]interface{}{{}}
		},
	})

	// Set up location
	vm.Set("location", map[string]interface{}{
		"href":     "https://nopecha.com/captcha/cloudflare",
		"origin":   "https://nopecha.com",
		"hostname": "nopecha.com",
		"pathname": "/captcha/cloudflare",
		"search":   "",
		"hash":     "",
	})

	// Set up history
	vm.Set("history", map[string]interface{}{
		"replaceState": func() {},
		"pushState":    func() {},
	})

	// Run the script.
	_, err := vm.RunString(deobfuscatedSource)
	if err != nil {
		// The script may fail due to missing browser APIs, but it may have
		// already computed the values we need.
		// Continue to extract what we can.
	}

	result := &RuntimeConstants{}

	// Try to extract the RSA modulus.
	result.Modulus = extractBigIntFromVM(vm)
	result.Alphabet = extractString64FromVM(vm)
	result.Secret = extractSecret16FromVM(vm)

	// Also try to extract from _cf_chl_opt.
	if cfOpt := vm.Get("_cf_chl_opt"); cfOpt != nil {
		if obj := cfOpt.ToObject(vm); obj != nil {
			for _, key := range obj.Keys() {
				val := obj.Get(key)
				// Check if this is the RSA modulus (a BigInt or hex string).
				if s := val.String(); len(s) >= 128 && isHexString(s) {
					if n, ok := new(big.Int).SetString(s, 16); ok {
						result.Modulus = n
					}
				}
			}
		}
	}

	return result, nil
}

// RuntimeConstants holds values extracted by executing the deobfuscated script.
type RuntimeConstants struct {
	Modulus  *big.Int
	Alphabet string
	Secret   [16]byte
}

// HasModulus reports whether the RSA modulus was found.
func (r *RuntimeConstants) HasModulus() bool { return r.Modulus != nil }

// HasAlphabet reports whether the base64 alphabet was found.
func (r *RuntimeConstants) HasAlphabet() bool { return r.Alphabet != "" }

// String returns a summary.
func (r *RuntimeConstants) String() string {
	bits := 0
	if r.Modulus != nil {
		bits = r.Modulus.BitLen()
	}
	return fmt.Sprintf("RuntimeConstants{modulus: %d bits, alphabet: %d chars, secret: %d bytes}",
		bits, len(r.Alphabet), len(r.Secret))
}

// extractBigIntFromVM tries to find a BigInt value in the VM's global scope.
func extractBigIntFromVM(vm *goja.Runtime) *big.Int {
	// Scan all global variables.
	for _, name := range vm.Get("globalThis").ToObject(vm).Keys() {
		val := vm.Get(name)
		if val == nil {
			continue
		}
		s := val.String()
		// Check if it's a large decimal number (BigInt).
		if len(s) >= 200 && isAllDigits(s) {
			if n, ok := new(big.Int).SetString(s, 10); ok && n.BitLen() >= 512 {
				return n
			}
		}
		// Check if it's a hex string.
		if len(s) >= 200 && isHexString(s) {
			if n, ok := new(big.Int).SetString(s, 16); ok && n.BitLen() >= 512 {
				return n
			}
		}
		// Check if it's an array containing BigInt values.
		if obj := val.ToObject(vm); obj != nil {
			if obj.ClassName() == "Array" {
				for _, key := range obj.Keys() {
					elem := obj.Get(key)
					if elem == nil {
						continue
					}
					es := elem.String()
					if len(es) >= 200 && isAllDigits(es) {
						if n, ok := new(big.Int).SetString(es, 10); ok && n.BitLen() >= 512 {
							return n
						}
					}
				}
			}
		}
	}
	return nil
}

// extractString64FromVM tries to find a 64-character string.
func extractString64FromVM(vm *goja.Runtime) string {
	for _, name := range vm.Get("globalThis").ToObject(vm).Keys() {
		val := vm.Get(name)
		if val == nil {
			continue
		}
		s := val.String()
		if len(s) == 64 && isBase64Alphabet(s) {
			return s
		}
		// Also check arrays.
		if obj := val.ToObject(vm); obj != nil {
			if obj.ClassName() == "Array" {
				for _, key := range obj.Keys() {
					elem := obj.Get(key)
					if elem == nil {
						continue
					}
					es := elem.String()
					if len(es) == 64 && isBase64Alphabet(es) {
						return es
					}
				}
			}
		}
	}
	return ""
}

// extractSecret16FromVM tries to find a 16-character string.
func extractSecret16FromVM(vm *goja.Runtime) [16]byte {
	for _, name := range vm.Get("globalThis").ToObject(vm).Keys() {
		val := vm.Get(name)
		if val == nil {
			continue
		}
		s := val.String()
		if len(s) == 16 && isPrintableASCII(s) {
			var secret [16]byte
			copy(secret[:], s)
			return secret
		}
	}
	return [16]byte{}
}

func isHexString(s string) bool {
	for _, c := range strings.ToLower(s) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isBase64Alphabet(s string) bool {
	if len(s) != 64 {
		return false
	}
	seen := make(map[byte]bool)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c > 127 {
			return false
		}
		if seen[c] {
			return false
		}
		seen[c] = true
	}
	return true
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}

// ExtractRuntimeEncoderParams combines deobfuscation and runtime evaluation
// to extract encoder parameters from an obfuscated orchestrator script.
func ExtractRuntimeEncoderParams(source string) (*RuntimeConstants, string, error) {
	return ExtractRuntimeEncoderParamsWithConfig(source, nil)
}

// ExtractRuntimeEncoderParamsWithConfig is like ExtractRuntimeEncoderParams
// but accepts _cf_chl_opt values from the challenge page.
func ExtractRuntimeEncoderParamsWithConfig(source string, cfChlOpt map[string]string) (*RuntimeConstants, string, error) {
	deobf, err := DeobfuscateWithInlining(source)
	if err != nil {
		return nil, deobf, err
	}
	constants, err := EvaluateRuntimeConstantsWithConfig(deobf, cfChlOpt)
	if err != nil {
		return nil, deobf, err
	}
	return constants, deobf, nil
}

// FindBigIntCalls finds all BigInt(...) calls in the source and returns their
// string representations.
func FindBigIntCalls(source string) []string {
	rx := regexp.MustCompile(`BigInt\(([^)]+)\)`)
	var results []string
	for _, m := range rx.FindAllStringSubmatch(source, -1) {
		if len(m) >= 2 {
			results = append(results, m[1])
		}
	}
	return results
}
