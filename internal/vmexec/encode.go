// Package vmexec - encoder execution via goja.
//
// This file provides the EncodePayload function that loads the orchestrator
// JS, calls the runner with the initial program, and then calls the encoder
// to produce the encoded payload for POSTing to the challenge URL.
package vmexec

import (
	"encoding/base64"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dop251/goja"

	"github.com/cestrenium/turnpass/internal/deobfuscate"
)

// EncodePayloadResult holds the result of encoding a payload via the goja VM.
type EncodePayloadResult struct {
	// EncodedPayload is the encoded payload string ready to POST.
	EncodedPayload string
	// KeyTransformFunction is the source of the key transform function
	// returned by the runner.
	KeyTransformFunction string
	// Secret is the 16-byte key-transform secret (if found).
	Secret [16]byte
	// SecretFound reports whether the secret was found.
	SecretFound bool
	// Error is the first error encountered (if any).
	Error error
	// EncoderCallResult is the raw result of calling the encoder (for
	// debugging). This is a JSON string with type/value/length fields.
	EncoderCallResult string
}

// EncodePayload loads the orchestrator JS into a sandboxed goja runtime,
// calls the runner with the initial VM program, installs the key transform
// function, and then calls the encoder to produce the encoded payload.
//
// The orchestratorJS is the raw (obfuscated) orchestrator script.
// The runnerName and initialProgram are from the encoder extraction.
// The cfChlOptValues are from the challenge page HTML.
// The encoderName is the name of the encoder function (e.g. "Em").
//
// The encoderName is used to expose the encoder on window via source
// modification: replacing "Em=function(" with "window.__encoder=Em=function(".
func EncodePayload(orchestratorJS, runnerName, initialProgram, encoderName string, cfChlOptValues map[string]string) (*EncodePayloadResult, error) {
	result := &EncodePayloadResult{}

	if runnerName == "" || initialProgram == "" || encoderName == "" {
		return nil, fmt.Errorf("missing required parameters")
	}

	// Two-pronged approach:
	// 1. Hook XMLHttpRequest.send to capture payloads (in case the orchestrator
	//    calls send() during initialization)
	// 2. Modify the source to expose the encoder function on window (for direct
	//    calling after the runner call)
	//
	// For the source modification, we deobfuscate the source first (to resolve
	// lazy-init patterns) and then search for the `send(encoderName(` pattern
	// to find the exact encoder assignment to modify.
	deobfSrc := orchestratorJS
	if deobf, err := deobfuscate.DeobfuscateWithInlining(orchestratorJS); err == nil {
		deobfSrc = deobf
	}

	// Search for the send(encoderName( pattern in the deobfuscated source.
	// Pattern: [...=`send`)](ENCODER(
	// The `send` may be inside a lazy-init: VAR||(VAR=`send`)
	// We match: `send`)]( followed by a function name and (
	rxSendCall := regexp.MustCompile("`send`\\)]\\(([a-zA-Z_$][\\w$]*)\\(")
	sendMatch := rxSendCall.FindStringSubmatch(deobfSrc)
	src := orchestratorJS // use raw source for goja execution
	if len(sendMatch) >= 2 {
		// Found the encoder name from the send call.
		encoderFromSend := sendMatch[1]
		// Find the encoder's assignment in the RAW source and modify it.
		// Use a word-boundary regex to find the exact assignment.
		rxEnc := regexp.MustCompile(`\b` + regexp.QuoteMeta(encoderFromSend) + `\s*=\s*function\s*\(`)
		if loc := rxEnc.FindStringIndex(src); loc != nil {
			src = src[:loc[0]] +
				`window.__encoder=` + encoderFromSend + `=function(` +
				src[loc[1]:]
		}
	} else if len(encoderName) > 1 {
		// Fallback: use the encoder name from AST analysis.
		rx := regexp.MustCompile(`\b` + regexp.QuoteMeta(encoderName) + `\s*=\s*function\s*\(`)
		if loc := rx.FindStringIndex(src); loc != nil {
			src = src[:loc[0]] +
				`window.__encoder=` + encoderName + `=function(` +
				src[loc[1]:]
		}
	}

	vm := goja.New()
	windowObj := setupSandbox(vm, cfChlOptValues)

	// Hook XMLHttpRequest.send to capture the payload.
	vm.RunString(`
                window.__captured_payload = null;
                var origXHROpen = XMLHttpRequest.prototype.open;
                var origXHRSend = XMLHttpRequest.prototype.send;
                XMLHttpRequest.prototype.open = function(method, url) {
                        this.__url = url;
                        return origXHROpen.apply(this, arguments);
                };
                XMLHttpRequest.prototype.send = function(body) {
                        if (body && typeof body === 'string' && body.length > 100) {
                                window.__captured_payload = body;
                                window.__captured_url = this.__url;
                        }
                };
        `)

	// Load the orchestrator JS (wrapped in try-catch).
	wrappedJS := "(function(){try{" + src + "\n}catch(e){window.__orch_error=e.message;}})();"
	done := make(chan error, 1)
	go func() {
		_, err := vm.RunString(wrappedJS)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			result.Error = err
		}
	case <-time.After(15 * time.Second):
		return nil, fmt.Errorf("orchestrator execution timed out")
	}

	// Check if the runner is installed.
	runnerVal := windowObj.Get(runnerName)
	if runnerVal == nil || goja.IsUndefined(runnerVal) || goja.IsNull(runnerVal) {
		// Try _cf_chl_opt
		if cfOpt := windowObj.Get("_cf_chl_opt"); cfOpt != nil {
			if obj := cfOpt.ToObject(vm); obj != nil {
				runnerVal = obj.Get(runnerName)
			}
		}
	}
	// Search all window properties for the runner (it may be on a nested object).
	if runnerVal == nil || goja.IsUndefined(runnerVal) || goja.IsNull(runnerVal) {
		for _, key := range windowObj.Keys() {
			val := windowObj.Get(key)
			if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
				continue
			}
			if obj := val.ToObject(vm); obj != nil {
				if rv := obj.Get(runnerName); rv != nil && !goja.IsUndefined(rv) && !goja.IsNull(rv) {
					runnerVal = rv
					break
				}
			}
		}
	}
	// Also try a JS-based search for nested properties.
	if runnerVal == nil || goja.IsUndefined(runnerVal) || goja.IsNull(runnerVal) {
		searchResult, _ := vm.RunString(fmt.Sprintf(`
                        (function() {
                                var name = %q;
                                function search(obj, depth) {
                                        if (!obj || depth > 2) return null;
                                        try {
                                                if (typeof obj[name] === 'function') return obj[name];
                                                var keys = Object.keys(obj);
                                                for (var i = 0; i < keys.length; i++) {
                                                        try {
                                                                var v = obj[keys[i]];
                                                                if (v && typeof v === 'object') {
                                                                        var r = search(v, depth + 1);
                                                                        if (r) return r;
                                                                }
                                                        } catch(e) {}
                                                }
                                        } catch(e) {}
                                        return null;
                                }
                                return search(window, 0);
                        })()
                `, runnerName))
		if searchResult != nil && !goja.IsUndefined(searchResult) && !goja.IsNull(searchResult) {
			runnerVal = searchResult
		}
	}
	if runnerVal == nil || goja.IsUndefined(runnerVal) || goja.IsNull(runnerVal) {
		return nil, fmt.Errorf("runner %q not found on window or any global object", runnerName)
	}

	// Install the runner on window for easy calling.
	windowObj.Set("__runner_fn", runnerVal)

	// Call the runner with the initial program.
	runnerCall := fmt.Sprintf(`try{window.__runner_result=window.__runner_fn(%q);}catch(e){window.__runner_error=e.message;}`, initialProgram)
	go func() {
		_, err := vm.RunString(runnerCall)
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}

	// Capture the key transform function source.
	if resVal := windowObj.Get("__runner_result"); resVal != nil && !goja.IsUndefined(resVal) {
		result.KeyTransformFunction = resVal.String()
	}

	// Check if the XHR hook captured a payload during the orchestrator load
	// or the runner call. The orchestrator's IIFE may call send() as part
	// of its initialization.
	if payloadVal := windowObj.Get("__captured_payload"); payloadVal != nil && !goja.IsUndefined(payloadVal) && !goja.IsNull(payloadVal) {
		result.EncodedPayload = payloadVal.String()
	}

	// If no payload was captured, try installing the runner result as the
	// missing global and triggering the encoder by calling send-related
	// functions. The orchestrator's IIFE may have a deferred send that
	// wasn't triggered because the VM didn't complete.
	if result.EncodedPayload == "" {
		// Install the runner result on all undefined hex globals.
		hexGlobals := []string{}
		for _, k := range windowObj.Keys() {
			if len(k) >= 24 && k[0] == '_' && isHexName(k) {
				hexGlobals = append(hexGlobals, k)
			}
		}
		// Find missing globals via ReferenceError and install the runner result.
		missingResult, _ := vm.RunString(`
                        try {
                                // Try to trigger the encoder by accessing _cf_chl_opt properties
                                // that the VM should have set up.
                                var opts = window._cf_chl_opt;
                                // Look for any function on opts that might be the encoder trigger.
                                var keys = Object.keys(opts);
                                for (var i = 0; i < keys.length; i++) {
                                        try {
                                                var v = opts[keys[i]];
                                                if (typeof v === 'function') {
                                                        v();
                                                }
                                        } catch(e) {
                                                var msg = e.message || String(e);
                                                var m = msg.match(/([a-f0-9_]{25,}) is not defined/);
                                                if (m) {
                                                        window.__missing = m[1];
                                                }
                                        }
                                }
                        } catch(e) {}
                `)
		_ = missingResult

		// Install the runner result under the missing global name.
		if missingVal := windowObj.Get("__missing"); missingVal != nil && !goja.IsUndefined(missingVal) {
			missingGlobal := missingVal.String()
			if missingGlobal != "" && missingGlobal != "undefined" {
				vm.RunString(fmt.Sprintf(`window.%s = window.__runner_result;`, missingGlobal))
			}
		}

		// Also install under all undefined hex globals.
		for _, name := range hexGlobals {
			val := windowObj.Get(name)
			if val == nil || goja.IsUndefined(val) {
				vm.RunString(fmt.Sprintf(`window.%s = window.__runner_result;`, name))
			}
		}

		// Check again if the payload was captured after installing globals.
		if payloadVal := windowObj.Get("__captured_payload"); payloadVal != nil && !goja.IsUndefined(payloadVal) && !goja.IsNull(payloadVal) {
			result.EncodedPayload = payloadVal.String()
		}
	}

	// If we still don't have a payload, try calling the encoder directly
	// (only if it was exposed via source modification).
	if result.EncodedPayload == "" {
		if encVal := windowObj.Get("__encoder"); encVal != nil && !goja.IsUndefined(encVal) && !goja.IsNull(encVal) {
			// Try calling the encoder. The encoder may:
			// 1. Return the encoded payload string
			// 2. Throw the encoded payload (using throw for control flow)
			// 3. Throw a TypeError (VM dispatch failure)
			// We capture all possible outcomes.
			encResult, _ := vm.RunString(`
                                try {
                                        var result = window.__encoder(window._cf_chl_opt);
                                        if (result !== undefined && result !== null) {
                                                JSON.stringify({type: 'return', value: String(result)});
                                        } else {
                                                '{"type":"return","value":""}';
                                        }
                                } catch(e) {
                                        JSON.stringify({type: 'throw', value: String(e), length: String(e).length, name: e.name, message: e.message});
                                }
                        `)
			if encResult != nil {
				s := encResult.String()
				// If the thrown value is long enough, it's likely the payload.
				if len(s) > 200 {
					result.EncodedPayload = s
				}
				// Store the raw result for debugging.
				result.EncoderCallResult = s
			}
			// Check XHR hook again after encoder call.
			if result.EncodedPayload == "" {
				if payloadVal := windowObj.Get("__captured_payload"); payloadVal != nil && !goja.IsUndefined(payloadVal) && !goja.IsNull(payloadVal) {
					result.EncodedPayload = payloadVal.String()
				}
			}
		}
	}

	return result, nil
}

// isHexName checks if a string is a hex-named property (underscore + hex chars).
func isHexName(s string) bool {
	if len(s) < 2 || s[0] != '_' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Suppress unused import warnings.
var (
	_ = base64.StdEncoding
	_ = math.Floor
	_ = os.ReadFile
	_ = strings.HasPrefix
)
