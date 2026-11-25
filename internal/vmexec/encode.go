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

	// Modify the orchestrator source to expose the encoder on window.
	src := orchestratorJS
	rx := regexp.MustCompile(`\b` + regexp.QuoteMeta(encoderName) + `\s*=\s*function\s*\(`)
	src = rx.ReplaceAllString(src, `window.__encoder=`+encoderName+`=function(`)

	vm := goja.New()
	windowObj := setupSandbox(vm, cfChlOptValues)

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
	if runnerVal == nil || goja.IsUndefined(runnerVal) || goja.IsNull(runnerVal) {
		return nil, fmt.Errorf("runner %q not found", runnerName)
	}

	// Call the runner with the initial program.
	runnerCall := fmt.Sprintf(`try{window.__runner_result=window.%s(%q);}catch(e){window.__runner_error=e.message;}`, runnerName, initialProgram)
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

	// Find all hex-named globals that the orchestrator installed.
	// These are the VM-installed globals that the encoder needs.
	// The key transform function (runner result) needs to be installed
	// under the name that the encoder expects.
	hexGlobals := []string{}
	for _, k := range windowObj.Keys() {
		if len(k) >= 24 && k[0] == '_' && isHexName(k) {
			hexGlobals = append(hexGlobals, k)
		}
	}

	// Find the missing global name that the encoder needs.
	// We do this by calling the encoder and capturing the ReferenceError.
	missingGlobal := ""
	if encVal := windowObj.Get("__encoder"); encVal != nil && !goja.IsUndefined(encVal) {
		missingResult, _ := vm.RunString(`
			try {
				window.__encoder(window._cf_chl_opt);
			} catch(e) {
				var msg = e.message || String(e);
				var m = msg.match(/([a-f0-9_]{25,}) is not defined/);
				if (m) m[1]; else '';
			}
		`)
		if missingResult != nil {
			missingGlobal = missingResult.String()
		}
	}

	// If we found a missing global, install the runner result under that name.
	if missingGlobal != "" && missingGlobal != "undefined" {
		vm.RunString(fmt.Sprintf(`window.%s = window.__runner_result;`, missingGlobal))
	}

	// Also try installing the runner result under all hex globals that
	// are currently undefined (in case there are multiple missing globals).
	for _, name := range hexGlobals {
		val := windowObj.Get(name)
		if val == nil || goja.IsUndefined(val) {
			vm.RunString(fmt.Sprintf(`window.%s = window.__runner_result;`, name))
		}
	}

	// Now call the encoder to produce the encoded payload.
	// The encoder may throw the encoded payload as a string (using throw
	// for control flow in the obfuscated code).
	encResult, _ := vm.RunString(`
		try {
			var result = window.__encoder(window._cf_chl_opt);
			// If the encoder returned a value, use it.
			if (result !== undefined && result !== null) {
				String(result);
			} else {
				'';
			}
		} catch(e) {
			// The encoder may throw the encoded payload as a string.
			var s = String(e);
			// If the thrown value looks like an encoded payload (long string
			// with base64-like characters), return it.
			if (s.length > 100) {
				s;
			} else {
				// Re-throw to capture the actual error.
				throw e;
			}
		}
	`)
	if encResult != nil {
		encoded := encResult.String()
		if len(encoded) > 100 {
			result.EncodedPayload = encoded
		}
	}

	// If we didn't get the payload from the return/throw, try again.
	// The encoder might need multiple calls to set up state.
	if result.EncodedPayload == "" {
		encResult2, _ := vm.RunString(`
			try {
				var result = window.__encoder(window._cf_chl_opt);
				if (result !== undefined && result !== null) {
					String(result);
				} else {
					'';
				}
			} catch(e) {
				var s = String(e);
				if (s.length > 100) { s; } else { ''; }
			}
		`)
		if encResult2 != nil {
			encoded := encResult2.String()
			if len(encoded) > 100 {
				result.EncodedPayload = encoded
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
