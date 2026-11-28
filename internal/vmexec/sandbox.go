// Package vmexec provides sandboxed execution of the Cloudflare challenge
// VM using goja. It loads the orchestrator JavaScript, calls the program
// runner with the initial VM program, and captures the window globals
// that the VM installs — most importantly the 16-byte key-transform secret
// and the obfuscated-to-standard property name mapping for _cf_chl_opt.
//
// This approach avoids the need for a full symbolic VM interpreter by
// letting goja execute the real (deobfuscated) VM code in a sandboxed
// environment with stubbed browser APIs.
package vmexec

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// Result holds the values extracted from a sandboxed VM execution.
type Result struct {
	// Secret is the 16-byte key-transform secret installed by the initial
	// VM program via window[name] = factory("secret").
	Secret [16]byte
	// SecretFound reports whether the secret was found.
	SecretFound bool
	// KeyTransform is the name of the window global that holds the key
	// transform function.
	KeyTransform string
	// InstalledGlobals maps window global names to their installed values
	// (as Go interfaces).
	InstalledGlobals map[string]interface{}
	// NewGlobals lists window global names that were installed by the
	// runner call (not present before).
	NewGlobals []string
	// Options is the _cf_chl_opt object after the VM runs.
	Options map[string]interface{}
	// WindowKeys is the list of all keys on the window object after execution.
	WindowKeys []string
	// Error is the first error encountered during execution (if any).
	Error error
	// RunnerError is the error from the runner call (if any), captured
	// from the try-catch wrapper.
	RunnerError string
	// RunnerResult is the return value of the runner call (as a string).
	RunnerResult string
	// NewOptions lists _cf_chl_opt keys that were added by the runner call.
	NewOptions []string
	// CapturedStrings lists all 16-byte strings captured during the runner
	// call via the Function.prototype.call/apply hook.
	CapturedStrings []string
}

// ExecuteOrchestrator loads the orchestrator JavaScript into a sandboxed
// goja runtime, then calls the program runner with the initial VM program.
// The runner is identified by runnerName (e.g. "_70d0bf09ea03c8d380276ae5").
//
// The initialProgram is the base64-encoded VM bytecode passed to the runner.
//
// cfChlOptValues are the _cf_chl_opt values from the challenge page HTML,
// used to initialize the sandbox environment.
func ExecuteOrchestrator(orchestratorJS, runnerName, initialProgram string, cfChlOptValues map[string]string) (*Result, error) {
	result := &Result{
		InstalledGlobals: make(map[string]interface{}),
		Options:          make(map[string]interface{}),
	}

	vm := goja.New()

	// Set up comprehensive browser API stubs.
	windowObj := setupSandbox(vm, cfChlOptValues)

	// Run the orchestrator JS to set up the VM class, runner, and helpers.
	// Wrap in try-catch so that errors don't prevent us from checking if the
	// runner was installed before the failure. Store the error message for
	// debugging.
	wrappedJS := "(function(){try{" + orchestratorJS + "\n}catch(e){window.__orch_error=e.message+':'+e.stack;}})();"

	// Use a timeout to prevent infinite loops.
	done := make(chan error, 1)
	go func() {
		_, err := vm.RunString(wrappedJS)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			// The orchestrator may fail due to missing browser APIs, but
			// the VM setup (class, runner, helpers) may have completed.
			result.Error = err
		}
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("orchestrator execution timed out")
	}

	// Check if the runner is installed on the window object.
	runnerVal := windowObj.Get(runnerName)
	if runnerVal == nil || goja.IsUndefined(runnerVal) || goja.IsNull(runnerVal) {
		// Try _cf_chl_opt (the runner may be installed there)
		if cfOpt := windowObj.Get("_cf_chl_opt"); cfOpt != nil {
			if obj := cfOpt.ToObject(vm); obj != nil {
				runnerVal = obj.Get(runnerName)
			}
		}
	}
	// If still not found, search all window properties for the runner.
	// The runner may be installed as a property on a global object:
	//   br[...]._hexname = function(VAR){...}
	// We search all object-valued window properties for a matching key.
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
	// Also try using goja to search (handles nested properties).
	if runnerVal == nil || goja.IsUndefined(runnerVal) || goja.IsNull(runnerVal) {
		searchResult, _ := vm.RunString(fmt.Sprintf(`
                        (function() {
                                var name = %q;
                                // Search window and all its object properties.
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
		// Runner not found — extract whatever globals were installed
		// before the orchestrator failed.
		extractWindowGlobals(vm, windowObj, result)
		identifyKeyTransform(result)
		return result, fmt.Errorf("runner %q not found on window or any global object", runnerName)
	}

	// Install a catch-all for undefined global references. The VM
	// constructor calls functions (like S9, FS, S0) that are installed
	// by the initial VM program. If the initial program didn't complete,
	// these are undefined, causing TypeError. We use a Proxy on the
	// global object to return a default function/object for undefined
	// properties, allowing the VM to continue.
	vm.RunString(`
                // Create a default function that returns 0 when called.
                function defaultFn() { return 0; }
                defaultFn.valueOf = function() { return 0; };
                defaultFn.toString = function() { return ''; };
                defaultFn.length = 0;

                // Create a default object that returns 0 for any property.
                var defaultObj = {
                    length: 0,
                    valueOf: function() { return 0; },
                    toString: function() { return ''; },
                    charCodeAt: function() { return 0; },
                    slice: function() { return ''; },
                    push: function() { return 0; },
                    pop: function() { return 0; },
                    indexOf: function() { return -1; }
                };

                // Wrap the global object so undefined properties return
                // defaultFn (for function calls) or defaultObj (for property
                // access). This prevents ReferenceError and TypeError when
                // the VM accesses globals that weren't installed.
                var globalProxy = new Proxy(window, {
                    get: function(target, prop) {
                        if (prop in target) {
                            return target[prop];
                        }
                        // Return a function that also acts as an object.
                        var f = function() { return 0; };
                        f.length = 0;
                        f.valueOf = function() { return 0; };
                        f.toString = function() { return ''; };
                        return f;
                    },
                    has: function() { return true; }
                });
        `)

	// Snapshot window keys before the runner call.
	beforeKeys := make(map[string]bool)
	for _, k := range windowObj.Keys() {
		beforeKeys[k] = true
	}
	// Snapshot _cf_chl_opt keys before the runner call.
	beforeOptKeys := make(map[string]bool)
	if cfOpt := windowObj.Get("_cf_chl_opt"); cfOpt != nil {
		if obj := cfOpt.ToObject(vm); obj != nil {
			for _, k := range obj.Keys() {
				beforeOptKeys[k] = true
			}
		}
	}

	// Call the runner with the initial program.
	callDone := make(chan error, 1)
	// Install the runner on window so we can call it by name.
	// The runner may have been found on a nested object, so we set it
	// directly on window for easy access.
	windowObj.Set("__runner_fn", runnerVal)

	go func() {
		_, err := vm.RunString(fmt.Sprintf(`try{window.__runner_result=window.__runner_fn(%q);}catch(e){window.__runner_error=e.message+':'+e.stack;}`, initialProgram))
		callDone <- err
	}()

	select {
	case err := <-callDone:
		if err != nil {
			// The VM execution may fail partway through, but the initial
			// program's window assignments may have already happened.
			if result.Error == nil {
				result.Error = err
			}
		}
	case <-time.After(10 * time.Second):
		// Timeout — the VM may have entered an infinite loop, but initial
		// assignments may have completed.
	}

	// Extract all window globals that were installed by the VM.
	extractWindowGlobals(vm, windowObj, result)

	// Track which keys are new (installed by the runner call).
	for _, k := range result.WindowKeys {
		if !beforeKeys[k] {
			result.NewGlobals = append(result.NewGlobals, k)
		}
	}

	// Check for runner error.
	if errVal := windowObj.Get("__runner_error"); errVal != nil && !goja.IsUndefined(errVal) {
		result.RunnerError = errVal.String()
	}

	// Check for runner result.
	if resVal := windowObj.Get("__runner_result"); resVal != nil && !goja.IsUndefined(resVal) {
		result.RunnerResult = resVal.String()
	}

	// Extract captured 16-byte string arguments from the function call hook.
	if caps := windowObj.Get("__captured_16byte_args"); caps != nil {
		if arr := caps.ToObject(vm); arr != nil {
			seen := make(map[string]bool)
			for _, k := range arr.Keys() {
				s := arr.Get(k).String()
				if len(s) == 16 && isPrintableASCII(s) && !seen[s] {
					seen[s] = true
					if !result.SecretFound {
						copy(result.Secret[:], s)
						result.SecretFound = true
					}
				}
			}
			// Store all captured strings for debugging.
			result.CapturedStrings = make([]string, 0, len(seen))
			for s := range seen {
				result.CapturedStrings = append(result.CapturedStrings, s)
			}
		}
	}

	// Track new _cf_chl_opt keys.
	if cfOpt := windowObj.Get("_cf_chl_opt"); cfOpt != nil {
		if obj := cfOpt.ToObject(vm); obj != nil {
			for _, k := range obj.Keys() {
				if !beforeOptKeys[k] {
					result.NewOptions = append(result.NewOptions, k)
				}
			}
		}
	}

	// Try to identify the key transform and extract the secret.
	identifyKeyTransform(result)

	return result, nil
}

// setupSandbox creates a comprehensive browser API sandbox in the goja runtime
// and returns the window object. Rather than creating a separate window object
// and overriding globalThis (which loses goja's built-in String, Number, etc.),
// we use goja's built-in global object as the window. This ensures that
// globalThis.String, globalThis.Number, etc. all work correctly.
func setupSandbox(vm *goja.Runtime, cfChlOptValues map[string]string) *goja.Object {
	// Use goja's built-in global object as the window.
	windowObj := vm.GlobalObject()
	vm.Set("window", windowObj)
	vm.Set("self", windowObj)
	// Do NOT override globalThis — let goja's built-in global remain.
	vm.Set("top", windowObj)
	vm.Set("parent", windowObj)
	vm.Set("frames", windowObj)

	// _cf_chl_opt — initialize with values from the challenge page.
	cfChlOpt := vm.NewObject()
	for k, v := range cfChlOptValues {
		cfChlOpt.Set(k, v)
	}
	windowObj.Set("_cf_chl_opt", cfChlOpt)

	// navigator
	nav := vm.NewObject()
	nav.Set("hardwareConcurrency", 4)
	nav.Set("userAgent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.3 Mobile/15E148 Safari/604.1")
	nav.Set("platform", "iPhone")
	nav.Set("languages", []string{"en-US", "en"})
	nav.Set("language", "en-US")
	nav.Set("vendor", "Apple Computer, Inc.")
	nav.Set("vendorSub", "")
	nav.Set("productSub", "20030107")
	nav.Set("maxTouchPoints", 5)
	nav.Set("appName", "Netscape")
	nav.Set("appVersion", "5.0")
	nav.Set("appCodeName", "Mozilla")
	nav.Set("onLine", true)
	nav.Set("cookieEnabled", true)
	nav.Set("doNotTrack", nil)
	nav.Set("webdriver", false)
	nav.Set("deviceMemory", 4)
	nav.Set("connection", vm.NewObject())
	windowObj.Set("navigator", nav)
	vm.Set("navigator", nav)

	// document
	doc := vm.NewObject()
	doc.Set("createElement", func(call goja.FunctionCall) goja.Value {
		tag := ""
		if len(call.Arguments) > 0 {
			tag = call.Arguments[0].String()
		}
		el := vm.NewObject()
		el.Set("tagName", tag)
		el.Set("nodeName", tag)
		el.Set("style", vm.NewObject())
		el.Set("children", vm.NewArray())
		el.Set("childNodes", vm.NewArray())
		el.Set("attributes", vm.NewObject())
		el.Set("classList", vm.NewObject())
		el.Set("dataset", vm.NewObject())
		el.Set("innerHTML", "")
		el.Set("textContent", "")
		el.Set("outerHTML", "")
		el.Set("appendChild", func(child goja.Value) goja.Value { return child })
		el.Set("removeChild", func(child goja.Value) goja.Value { return child })
		el.Set("insertBefore", func(child, ref goja.Value) goja.Value { return child })
		el.Set("setAttribute", func() {})
		el.Set("getAttribute", func() goja.Value { return goja.Null() })
		el.Set("removeAttribute", func() {})
		el.Set("hasAttribute", func() bool { return false })
		el.Set("addEventListener", func() {})
		el.Set("removeEventListener", func() {})
		el.Set("querySelector", func() goja.Value { return goja.Null() })
		el.Set("querySelectorAll", func() *goja.Object { return vm.NewArray() })
		el.Set("getElementsByTagName", func() *goja.Object { return vm.NewArray() })
		el.Set("getElementsByClassName", func() *goja.Object { return vm.NewArray() })
		el.Set("getContext", func() goja.Value { return goja.Null() })
		el.Set("toDataURL", func() string {
			return "data:,"
		})
		return el
	})
	doc.Set("createTextNode", func(text string) *goja.Object {
		tn := vm.NewObject()
		tn.Set("textContent", text)
		return tn
	})
	doc.Set("createDocumentFragment", func() *goja.Object {
		frag := vm.NewObject()
		frag.Set("appendChild", func(child goja.Value) goja.Value { return child })
		return frag
	})
	doc.Set("getElementsByTagName", func(tag string) *goja.Object {
		return vm.NewArray()
	})
	doc.Set("getElementsByClassName", func(cls string) *goja.Object {
		return vm.NewArray()
	})
	doc.Set("getElementById", func(id string) goja.Value {
		return goja.Null()
	})
	doc.Set("querySelector", func(sel string) goja.Value {
		return goja.Null()
	})
	doc.Set("querySelectorAll", func(sel string) *goja.Object {
		return vm.NewArray()
	})
	doc.Set("addEventListener", func() {})
	doc.Set("removeEventListener", func() {})
	doc.Set("readyState", "complete")
	doc.Set("cookie", "")
	doc.Set("referrer", "")
	doc.Set("URL", "https://nopecha.com/captcha/cloudflare")
	doc.Set("documentURI", "https://nopecha.com/captcha/cloudflare")
	doc.Set("domain", "nopecha.com")
	doc.Set("title", "Just a moment...")
	doc.Set("characterSet", "UTF-8")
	doc.Set("charset", "UTF-8")
	doc.Set("contentType", "text/html")
	doc.Set("compatMode", "CSS1Compat")
	doc.Set("visibilityState", "visible")
	doc.Set("hidden", false)
	doc.Set("head", vm.NewObject())
	doc.Set("body", vm.NewObject())
	doc.Set("documentElement", vm.NewObject())
	doc.Set("createEvent", func() *goja.Object {
		e := vm.NewObject()
		e.Set("initCustomEvent", func() {})
		return e
	})
	doc.Set("createComment", func(text string) *goja.Object {
		return vm.NewObject()
	})
	windowObj.Set("document", doc)
	vm.Set("document", doc)

	// location
	loc := vm.NewObject()
	loc.Set("href", "https://nopecha.com/captcha/cloudflare")
	loc.Set("origin", "https://nopecha.com")
	loc.Set("hostname", "nopecha.com")
	loc.Set("host", "nopecha.com")
	loc.Set("pathname", "/captcha/cloudflare")
	loc.Set("search", "")
	loc.Set("hash", "")
	loc.Set("protocol", "https:")
	loc.Set("port", "")
	loc.Set("assign", func() {})
	loc.Set("replace", func() {})
	loc.Set("reload", func() {})
	loc.Set("toString", func() string {
		return "https://nopecha.com/captcha/cloudflare"
	})
	windowObj.Set("location", loc)
	vm.Set("location", loc)

	// history
	hist := vm.NewObject()
	hist.Set("replaceState", func() {})
	hist.Set("pushState", func() {})
	hist.Set("back", func() {})
	hist.Set("forward", func() {})
	hist.Set("go", func() {})
	hist.Set("length", 1)
	hist.Set("state", goja.Null())
	windowObj.Set("history", hist)
	vm.Set("history", hist)

	// screen
	screen := vm.NewObject()
	screen.Set("width", 390)
	screen.Set("height", 844)
	screen.Set("availWidth", 390)
	screen.Set("availHeight", 844)
	screen.Set("availLeft", 0)
	screen.Set("availTop", 0)
	screen.Set("colorDepth", 30)
	screen.Set("pixelDepth", 30)
	screen.Set("orientation", vm.NewObject())
	windowObj.Set("screen", screen)
	vm.Set("screen", screen)

	// performance
	startTime := time.Now()
	perf := vm.NewObject()
	perf.Set("now", func() float64 {
		return float64(time.Since(startTime).Microseconds()) / 1000.0
	})
	perf.Set("timeOrigin", float64(startTime.UnixMilli()))
	timing := vm.NewObject()
	timing.Set("navigationStart", float64(startTime.UnixMilli()))
	timing.Set("fetchStart", float64(startTime.UnixMilli()))
	timing.Set("domainLookupStart", float64(startTime.UnixMilli()))
	timing.Set("domainLookupEnd", float64(startTime.UnixMilli()))
	timing.Set("connectStart", float64(startTime.UnixMilli()))
	timing.Set("connectEnd", float64(startTime.UnixMilli()))
	timing.Set("requestStart", float64(startTime.UnixMilli()))
	timing.Set("responseStart", float64(startTime.UnixMilli()))
	timing.Set("responseEnd", float64(startTime.UnixMilli()))
	timing.Set("domLoading", float64(startTime.UnixMilli()))
	timing.Set("domComplete", float64(startTime.UnixMilli()))
	timing.Set("loadEventEnd", float64(startTime.UnixMilli()))
	perf.Set("timing", timing)
	perf.Set("getEntries", func() *goja.Object { return vm.NewArray() })
	perf.Set("getEntriesByType", func(t string) *goja.Object { return vm.NewArray() })
	perf.Set("getEntriesByName", func(n string) *goja.Object { return vm.NewArray() })
	perf.Set("mark", func() {})
	perf.Set("measure", func() {})
	perf.Set("clearMarks", func() {})
	perf.Set("clearMeasures", func() {})
	windowObj.Set("performance", perf)
	vm.Set("performance", perf)

	// Timers
	timerID := 0
	windowObj.Set("setTimeout", func(call goja.FunctionCall) goja.Value {
		timerID++
		// Don't actually call the callback — just return a fake timer ID.
		return vm.ToValue(timerID)
	})
	vm.Set("setTimeout", windowObj.Get("setTimeout"))
	windowObj.Set("setInterval", func(call goja.FunctionCall) goja.Value {
		timerID++
		return vm.ToValue(timerID)
	})
	vm.Set("setInterval", windowObj.Get("setInterval"))
	windowObj.Set("clearTimeout", func(id int) {})
	vm.Set("clearTimeout", windowObj.Get("clearTimeout"))
	windowObj.Set("clearInterval", func(id int) {})
	vm.Set("clearInterval", windowObj.Get("clearInterval"))
	windowObj.Set("requestAnimationFrame", func(call goja.FunctionCall) goja.Value {
		timerID++
		return vm.ToValue(timerID)
	})
	vm.Set("requestAnimationFrame", windowObj.Get("requestAnimationFrame"))
	windowObj.Set("cancelAnimationFrame", func(id int) {})
	vm.Set("cancelAnimationFrame", windowObj.Get("cancelAnimationFrame"))
	windowObj.Set("queueMicrotask", func(call goja.FunctionCall) {
		// Don't execute microtasks.
	})
	vm.Set("queueMicrotask", windowObj.Get("queueMicrotask"))

	// Event listeners
	windowObj.Set("addEventListener", func() {})
	vm.Set("addEventListener", windowObj.Get("addEventListener"))
	windowObj.Set("removeEventListener", func() {})
	vm.Set("removeEventListener", windowObj.Get("removeEventListener"))
	windowObj.Set("dispatchEvent", func() bool { return true })
	vm.Set("dispatchEvent", windowObj.Get("dispatchEvent"))

	// XMLHttpRequest
	vm.Set("XMLHttpRequest", func() *goja.Object {
		xhr := vm.NewObject()
		xhr.Set("open", func() {})
		xhr.Set("send", func() {})
		xhr.Set("setRequestHeader", func() {})
		xhr.Set("abort", func() {})
		xhr.Set("getAllResponseHeaders", func() string { return "" })
		xhr.Set("getResponseHeader", func() string { return "" })
		xhr.Set("overrideMimeType", func() {})
		xhr.Set("addEventListener", func() {})
		xhr.Set("removeEventListener", func() {})
		xhr.Set("readyState", 0)
		xhr.Set("status", 0)
		xhr.Set("statusText", "")
		xhr.Set("responseText", "")
		xhr.Set("response", "")
		xhr.Set("responseType", "")
		xhr.Set("responseURL", "")
		xhr.Set("timeout", 0)
		xhr.Set("withCredentials", false)
		xhr.Set("upload", vm.NewObject())
		return xhr
	})

	// fetch (returns a rejected promise to avoid hanging)
	vm.Set("fetch", func() *goja.Promise {
		p, _, _ := vm.NewPromise()
		return p
	})

	// atob / btoa — base64 encode/decode. Goja does NOT have these built in
	// (they're browser APIs, not part of the JS spec). The orchestrator uses
	// atob() extensively to decode base64 strings.
	vm.Set("atob", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		s := call.Arguments[0].String()
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			// Try without padding
			decoded, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return goja.Undefined()
			}
		}
		// Convert to a JS string (binary string — each byte is a char code).
		result := make([]uint16, len(decoded))
		for i, b := range decoded {
			result[i] = uint16(b)
		}
		return vm.ToValue(stringFromUint16(result))
	})
	windowObj.Set("atob", vm.Get("atob"))

	vm.Set("btoa", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		s := call.Arguments[0].String()
		// Convert string to bytes (each char code mod 256).
		b := make([]byte, len(s))
		for i, c := range s {
			b[i] = byte(c & 0xFF)
		}
		return vm.ToValue(base64.StdEncoding.EncodeToString(b))
	})
	windowObj.Set("btoa", vm.Get("btoa"))

	// crypto
	cryptoObj := vm.NewObject()
	cryptoObj.Set("getRandomValues", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) > 0 {
			return call.Arguments[0]
		}
		return goja.Undefined()
	})
	cryptoObj.Set("randomUUID", func() string {
		return "00000000-0000-4000-8000-000000000000"
	})
	subtle := vm.NewObject()
	subtle.Set("digest", func() *goja.Promise { p, _, _ := vm.NewPromise(); return p })
	subtle.Set("encrypt", func() *goja.Promise { p, _, _ := vm.NewPromise(); return p })
	subtle.Set("decrypt", func() *goja.Promise { p, _, _ := vm.NewPromise(); return p })
	subtle.Set("importKey", func() *goja.Promise { p, _, _ := vm.NewPromise(); return p })
	subtle.Set("exportKey", func() *goja.Promise { p, _, _ := vm.NewPromise(); return p })
	subtle.Set("sign", func() *goja.Promise { p, _, _ := vm.NewPromise(); return p })
	subtle.Set("verify", func() *goja.Promise { p, _, _ := vm.NewPromise(); return p })
	cryptoObj.Set("subtle", subtle)
	windowObj.Set("crypto", cryptoObj)
	vm.Set("crypto", cryptoObj)

	// TextEncoder/TextDecoder — proper constructors with `new` support.
	// The orchestrator uses `new TextEncoder().encode(str)` which returns
	// a Uint8Array. Goja needs the ConstructorCall signature to support `new`.
	vm.Set("TextEncoder", func(call goja.ConstructorCall) *goja.Object {
		this := call.This
		this.Set("encoding", "utf-8")
		this.Set("encode", func(call2 goja.FunctionCall) goja.Value {
			s := ""
			if len(call2.Arguments) > 0 {
				s = call2.Arguments[0].String()
			}
			b := []byte(s)
			arr := make([]interface{}, len(b))
			for i, c := range b {
				arr[i] = int(c)
			}
			// Return a Uint8Array-like object.
			result := vm.NewArray(arr)
			return result
		})
		this.Set("encodeInto", func() *goja.Object { return vm.NewObject() })
		return nil // use `this` as the return value
	})
	vm.Set("TextDecoder", func(call goja.ConstructorCall) *goja.Object {
		this := call.This
		this.Set("encoding", "utf-8")
		this.Set("decode", func(call2 goja.FunctionCall) goja.Value {
			return vm.ToValue("")
		})
		return nil
	})

	// Blob
	vm.Set("Blob", func(call goja.FunctionCall) *goja.Object {
		b := vm.NewObject()
		b.Set("size", 0)
		b.Set("type", "application/octet-stream")
		b.Set("arrayBuffer", func() *goja.Promise { p, _, _ := vm.NewPromise(); return p })
		b.Set("text", func() *goja.Promise { p, _, _ := vm.NewPromise(); return p })
		return b
	})

	// URL
	urlObj := vm.NewObject()
	urlObj.Set("createObjectURL", func() string { return "blob:https://nopecha.com/00000000-0000-0000-0000-000000000000" })
	urlObj.Set("revokeObjectURL", func() {})
	vm.Set("URL", urlObj)

	// console (suppress all output)
	consoleObj := vm.NewObject()
	consoleObj.Set("log", func() {})
	consoleObj.Set("error", func() {})
	consoleObj.Set("warn", func() {})
	consoleObj.Set("info", func() {})
	consoleObj.Set("debug", func() {})
	consoleObj.Set("trace", func() {})
	consoleObj.Set("dir", func() {})
	consoleObj.Set("table", func() {})
	consoleObj.Set("group", func() {})
	consoleObj.Set("groupEnd", func() {})
	consoleObj.Set("time", func() {})
	consoleObj.Set("timeEnd", func() {})
	consoleObj.Set("assert", func() {})
	consoleObj.Set("count", func() {})
	vm.Set("console", consoleObj)

	// Worker stubs
	vm.Set("Worker", func() *goja.Object {
		w := vm.NewObject()
		w.Set("postMessage", func() {})
		w.Set("terminate", func() {})
		w.Set("addEventListener", func() {})
		w.Set("removeEventListener", func() {})
		return w
	})

	// MessageChannel/MessagePort
	vm.Set("MessageChannel", func() *goja.Object {
		mc := vm.NewObject()
		port := vm.NewObject()
		port.Set("postMessage", func() {})
		port.Set("close", func() {})
		port.Set("start", func() {})
		port.Set("addEventListener", func() {})
		mc.Set("port1", port)
		mc.Set("port2", port)
		return mc
	})

	// DOMException
	vm.Set("DOMException", func(call goja.FunctionCall) *goja.Object {
		e := vm.NewObject()
		if len(call.Arguments) > 0 {
			e.Set("message", call.Arguments[0].String())
		}
		if len(call.Arguments) > 1 {
			e.Set("name", call.Arguments[1].String())
		}
		return e
	})

	// ErrorEvent
	vm.Set("ErrorEvent", func() *goja.Object { return vm.NewObject() })

	// CustomEvent
	vm.Set("CustomEvent", func() *goja.Object { return vm.NewObject() })

	// Event
	vm.Set("Event", func() *goja.Object { return vm.NewObject() })

	// MutationObserver
	vm.Set("MutationObserver", func() *goja.Object {
		mo := vm.NewObject()
		mo.Set("observe", func() {})
		mo.Set("disconnect", func() {})
		mo.Set("takeRecords", func() *goja.Object { return vm.NewArray() })
		return mo
	})

	// ResizeObserver
	vm.Set("ResizeObserver", func() *goja.Object {
		ro := vm.NewObject()
		ro.Set("observe", func() {})
		ro.Set("unobserve", func() {})
		ro.Set("disconnect", func() {})
		return ro
	})

	// IntersectionObserver
	vm.Set("IntersectionObserver", func() *goja.Object {
		io := vm.NewObject()
		io.Set("observe", func() {})
		io.Set("unobserve", func() {})
		io.Set("disconnect", func() {})
		io.Set("takeRecords", func() *goja.Object { return vm.NewArray() })
		return io
	})

	// localStorage/sessionStorage
	storageObj := vm.NewObject()
	storageObj.Set("getItem", func() goja.Value { return goja.Null() })
	storageObj.Set("setItem", func() {})
	storageObj.Set("removeItem", func() {})
	storageObj.Set("clear", func() {})
	storageObj.Set("key", func() goja.Value { return goja.Null() })
	storageObj.Set("length", 0)
	windowObj.Set("localStorage", storageObj)
	windowObj.Set("sessionStorage", storageObj)
	vm.Set("localStorage", storageObj)
	vm.Set("sessionStorage", storageObj)

	// indexedDB
	idb := vm.NewObject()
	idb.Set("open", func() *goja.Object {
		req := vm.NewObject()
		req.Set("result", vm.NewObject())
		return req
	})
	windowObj.Set("indexedDB", idb)
	vm.Set("indexedDB", idb)

	// No-op stubs for misc browser APIs
	noopStubs := []string{
		"alert", "confirm", "prompt", "scroll", "scrollTo", "scrollBy",
		"print", "focus", "blur", "close", "stop", "open", "postMessage",
		"getComputedStyle", "matchMedia", "getSelection",
		"reportError", "structuredClone",
	}
	for _, name := range noopStubs {
		windowObj.Set(name, func() {})
		vm.Set(name, windowObj.Get(name))
	}

	// window properties that should return values
	windowObj.Set("innerWidth", 390)
	windowObj.Set("innerHeight", 844)
	windowObj.Set("outerWidth", 390)
	windowObj.Set("outerHeight", 844)
	windowObj.Set("scrollX", 0)
	windowObj.Set("scrollY", 0)
	windowObj.Set("pageXOffset", 0)
	windowObj.Set("pageYOffset", 0)
	windowObj.Set("screenX", 0)
	windowObj.Set("screenY", 0)
	windowObj.Set("screenLeft", 0)
	windowObj.Set("screenTop", 0)
	windowObj.Set("devicePixelRatio", 3)
	windowObj.Set("isSecureContext", true)
	windowObj.Set("origin", "https://nopecha.com")
	windowObj.Set("name", "")
	windowObj.Set("status", "")
	windowObj.Set("closed", false)
	windowObj.Set("length", 0)
	windowObj.Set("opener", goja.Null())
	windowObj.Set("frameElement", goja.Null())

	// Device events
	windowObj.Set("DeviceOrientationEvent", vm.NewObject())
	windowObj.Set("DeviceMotionEvent", vm.NewObject())

	// Storage stub
	windowObj.Set("Storage", vm.NewObject())

	// CSS
	vm.Set("CSS", vm.NewObject())

	// HTMLElement stubs
	vm.Set("HTMLElement", vm.NewObject())
	vm.Set("HTMLCanvasElement", vm.NewObject())
	vm.Set("HTMLImageElement", vm.NewObject())
	vm.Set("HTMLVideoElement", vm.NewObject())
	vm.Set("HTMLInputElement", vm.NewObject())
	vm.Set("HTMLFormElement", vm.NewObject())

	// WebGL stubs
	vm.Set("WebGLRenderingContext", vm.NewObject())
	vm.Set("WebGL2RenderingContext", vm.NewObject())

	// OffscreenCanvas
	vm.Set("OffscreenCanvas", func() *goja.Object {
		c := vm.NewObject()
		c.Set("getContext", func() goja.Value { return goja.Null() })
		c.Set("width", 0)
		c.Set("height", 0)
		return c
	})

	// Set up BigInt support (goja may need this)
	// goja supports BigInt natively via goja.BigInt()

	return windowObj
}

// extractWindowGlobals reads all properties from the window object after
// VM execution and stores them in the result. Only primitive values (strings,
// numbers, booleans) are exported to avoid OOM from circular references or
// large objects.
func extractWindowGlobals(vm *goja.Runtime, windowObj *goja.Object, result *Result) {
	keys := windowObj.Keys()
	result.WindowKeys = keys

	for _, key := range keys {
		val := windowObj.Get(key)
		if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
			continue
		}

		// Only export primitive values to avoid OOM and false positives.
		exportType := val.ExportType()
		if exportType == nil {
			continue
		}
		typeName := exportType.String()
		switch typeName {
		case "string":
			s := val.String()
			result.InstalledGlobals[key] = s
			// Check if this is a 16-byte string (potential secret).
			// Skip strings that look like Go type descriptions (start with '<').
			if len(s) == 16 && isPrintableASCII(s) && !strings.HasPrefix(s, "<") {
				if !result.SecretFound {
					copy(result.Secret[:], s)
					result.SecretFound = true
					result.KeyTransform = key
				}
			}
		case "int", "int64", "float64", "float32":
			result.InstalledGlobals[key] = val.Export()
		case "bool":
			result.InstalledGlobals[key] = val.ToBoolean()
		default:
			// Skip functions, objects, arrays — store type name only.
			result.InstalledGlobals[key] = typeName
		}
	}

	// Also extract _cf_chl_opt options.
	if cfOpt := windowObj.Get("_cf_chl_opt"); cfOpt != nil {
		if obj := cfOpt.ToObject(vm); obj != nil {
			for _, key := range obj.Keys() {
				val := obj.Get(key)
				if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
					continue
				}
				result.Options[key] = val.String()
			}
		}
	}
}

// identifyKeyTransform tries to identify which window global is the key
// transform function and extract its associated secret.
//
// The key transform is installed as window[name] = factory("secret") where
// factory is a function that builds a function from a constant string.
// The resulting value is a function, and the secret is the string argument
// to the factory call.
//
// Since we can't easily trace which factory call produced which window global
// in goja, we use heuristics:
//  1. Look for window globals that are functions.
//  2. For each function global, check if its source contains charCodeAt (the
//     key transform reads the secret with charCodeAt).
//  3. The secret is the 16-byte string that the function's closure captured.
func identifyKeyTransform(result *Result) {
	for name, val := range result.InstalledGlobals {
		// The key transform is a function — skip non-string values.
		// We look for 16-byte strings that could be the secret.
		if s, ok := val.(string); ok && len(s) == 16 && isPrintableASCII(s) {
			if !result.SecretFound {
				copy(result.Secret[:], s)
				result.SecretFound = true
				result.KeyTransform = name
			}
		}
	}
}

// exportValue converts a goja value to a Go interface.
func exportValue(vm *goja.Runtime, val goja.Value) interface{} {
	if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
		return nil
	}
	if val.ToBoolean() {
		// Could be bool or other truthy value.
		if s := val.String(); s == "true" {
			return true
		}
	}
	// Try string first (most common for our use case).
	return val.Export()
}

// nil2val returns goja.Null() if v is nil, otherwise v.
func nil2val(vm *goja.Runtime, v interface{}) goja.Value {
	if v == nil {
		return goja.Null()
	}
	return vm.ToValue(v)
}

// isPrintableASCII checks whether s consists of printable ASCII characters.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}

// stringFromUint16 converts a []uint16 to a Go string, treating each uint16
// as a UTF-16 code unit. This is used by atob to produce a "binary string"
// where each byte is represented as a character with that code point.
func stringFromUint16(chars []uint16) string {
	runes := make([]rune, len(chars))
	for i, c := range chars {
		runes[i] = rune(c)
	}
	return string(runes)
}

// DecodeInitialProgram base64-decodes the initial VM program string.
func DecodeInitialProgram(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b64)
}

// Float64 helper for performance.now()
var _ = math.Floor
