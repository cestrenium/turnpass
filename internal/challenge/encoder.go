// Package challenge - encoder parameter extraction.
//
// This file extracts the session's encoding constants from the iframe or
// orchestrator JavaScript: the base64 alphabet, RSA modulus, key-transform
// secret, the encoder function name, and the key-transform function name.
//
// The approach mirrors cfsolve's src/challenge/program.rs:
//   - Find the program runner installation: <global>.<name> = function(p){ return <run>(new <Class>(p), pc, key, []); }
//   - Find calls to the runner with a literal string argument → the initial VM program (base64).
//   - Find the encoder: the function whose result is passed to send().
//   - Find the alphabet: a string with 64 distinct ASCII chars.
//   - Find the modulus: a 1024-bit BigInt, possibly in a VAR||(VAR=`0xHEX`) lazy-init pattern.
//   - Find the key-transform name: an unbound global called from the encoder's definition.
//   - The 16-byte secret comes from VM execution (installed::read); we also scan the source for any obvious 16-byte string as a fallback.
package challenge

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/token"
)

// EncoderParams holds the session's encoding constants extracted from the
// iframe JavaScript: the base64 alphabet, RSA modulus, and key-transform
// secret.
type EncoderParams struct {
	// Alphabet is the 64-character base64 alphabet used by the session.
	Alphabet string
	// Modulus is the RSA modulus (1024-bit) used to encrypt the seed.
	Modulus *big.Int
	// Secret is the 16-byte key-transform secret.
	Secret [16]byte
	// KeyTransform is the name of the function the VM defines at runtime
	// that applies the key transform.
	KeyTransform string
	// Encoder is the name of the function whose result is handed to send().
	Encoder string
	// InitialProgram is the base64-encoded initial VM program passed to the
	// program runner. Decoding this and running the VM is what installs the
	// key transform on window[].
	InitialProgram string
	// RunnerName is the name of the program runner function.
	RunnerName string
	// VMClass is the name of the VM class.
	VMClass string
	// RunFunc is the name of the VM's run function.
	RunFunc string
	// InitialPC is the initial program counter from the runner installation.
	InitialPC float64
	// InitialKey is the initial dispatch key from the runner installation.
	InitialKey float64
}

var (
	// Matches BigInt("0x...") calls.
	rxBigInt = regexp.MustCompile(`BigInt\s*\(\s*["']0x([0-9a-fA-F]+)["']\s*\)`)
	// Matches BigInt(VAR||(VAR=`0x...`)) calls (lazy-init pattern, BigInt wrapping).
	rxBigIntLazy = regexp.MustCompile("BigInt\\s*\\(\\s*\\w+\\|\\|\\(\\w+=`0x([0-9a-fA-F]+)`\\)\\s*\\)")
	// Matches the actual pattern observed in real Cloudflare: He(BigInt, VAR||(VAR=`0xHEX`)).
	// The lazy-init expression can appear as an argument to another function.
	rxLazyHex = regexp.MustCompile("\\w+\\|\\|\\(\\w+=`0x([0-9a-fA-F]+)`\\)")
	// Matches a bare 0xHEX literal with at least 256 hex chars (1024 bits).
	rxHexLiteral = regexp.MustCompile("0x([0-9a-fA-F]{256,})")
	// Matches string literals that could be base64 alphabets (64 distinct chars).
	// Includes $ character which Cloudflare uses in custom alphabets.
	rxString64 = regexp.MustCompile("[\"']([A-Za-z0-9+/=_\\-$]{64,65})[\"']")
	// Matches backtick string literals that could be base64 alphabets.
	rxString64Backtick = regexp.MustCompile("`([A-Za-z0-9+/=_\\-$]{64,65})`")
	// Matches string literals of exactly 16 characters (potential key secrets).
	rxString16 = regexp.MustCompile("[\"']([^\"']{16})[\"']")
	// Matches backtick string literals of exactly 16 characters.
	rxString16Backtick = regexp.MustCompile("`([^`]{16})`")
	// Matches the program runner installation:
	//   <global>.<name> = function(p){ return <run>(new <Class>(p), pc, key, []); }
	// We capture: name, run, class, pc, key.
	rxRunnerInstall = regexp.MustCompile(`(\w+)\s*=\s*function\s*\(\s*\w+\s*\)\s*\{\s*return\s+(\w+)\s*\(\s*new\s+(\w+)\s*\(\s*\w+\s*\)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*\[\s*\]\s*\)\s*\}\s*`)
)

// ExtractEncoderParams scans the iframe JavaScript source for the session's
// encoding constants: the base64 alphabet, RSA modulus, and key-transform
// secret. It uses regex scanning plus targeted AST analysis for the runner
// and encoder names.
func ExtractEncoderParams(iframeJS string) (*EncoderParams, error) {
	params := &EncoderParams{}

	// Regex-based extraction of modulus, alphabet, and secret.
	extractViaRegex(iframeJS, params)

	// AST-based extraction of runner, encoder, and initial program.
	// These don't have reliable regex counterparts.
	extractRunnerAndEncoder(iframeJS, params)

	// Validate that we found the required parameters.
	if params.Modulus == nil {
		return nil, fmt.Errorf("could not find RSA modulus in iframe JS")
	}
	if params.Alphabet == "" {
		return nil, fmt.Errorf("could not find base64 alphabet in iframe JS")
	}

	return params, nil
}

// extractViaRegex uses regex patterns to find the encoder parameters.
func extractViaRegex(iframeJS string, params *EncoderParams) {
	// Find the RSA modulus: try several patterns in order.
	if params.Modulus == nil {
		// Try BigInt("0x...") direct call.
		for _, m := range rxBigInt.FindAllStringSubmatch(iframeJS, -1) {
			if len(m) >= 2 {
				if mod := tryModulus(m[1]); mod != nil {
					params.Modulus = mod
					break
				}
			}
		}
	}
	if params.Modulus == nil {
		// Try BigInt(VAR||(VAR=`0xHEX`)).
		for _, m := range rxBigIntLazy.FindAllStringSubmatch(iframeJS, -1) {
			if len(m) >= 2 {
				if mod := tryModulus(m[1]); mod != nil {
					params.Modulus = mod
					break
				}
			}
		}
	}
	if params.Modulus == nil {
		// Try the bare lazy-init pattern VAR||(VAR=`0xHEX`).
		// (This is the actual pattern in current Cloudflare: He(BigInt, VAR||(VAR=`0xHEX`)))
		for _, m := range rxLazyHex.FindAllStringSubmatch(iframeJS, -1) {
			if len(m) >= 2 {
				if mod := tryModulus(m[1]); mod != nil {
					params.Modulus = mod
					break
				}
			}
		}
	}
	if params.Modulus == nil {
		// Try bare 0xHEX literals with 256+ hex chars.
		for _, m := range rxHexLiteral.FindAllStringSubmatch(iframeJS, -1) {
			if len(m) >= 2 {
				if mod := tryModulus(m[1]); mod != nil {
					params.Modulus = mod
					break
				}
			}
		}
	}

	// Find the base64 alphabet.
	if params.Alphabet == "" {
		for _, m := range rxString64.FindAllStringSubmatch(iframeJS, -1) {
			if len(m) >= 2 {
				candidate := m[1]
				if len(candidate) >= 64 {
					candidate = candidate[:64]
				}
				if isDistinctASCII(candidate) && len(candidate) == 64 {
					params.Alphabet = candidate
					break
				}
			}
		}
	}
	if params.Alphabet == "" {
		for _, m := range rxString64Backtick.FindAllStringSubmatch(iframeJS, -1) {
			if len(m) >= 2 {
				candidate := m[1]
				if len(candidate) >= 64 {
					candidate = candidate[:64]
				}
				if isDistinctASCII(candidate) && len(candidate) == 64 {
					params.Alphabet = candidate
					break
				}
			}
		}
	}

	// Find the key-transform secret (16-char string).
	// NOTE: in real Cloudflare, the secret is computed by the VM, not a
	// literal in the source. This scan is a fallback for older builds.
	if params.Secret == [16]byte{} {
		for _, m := range rxString16.FindAllStringSubmatch(iframeJS, -1) {
			if len(m) >= 2 {
				secret := m[1]
				if len(secret) == 16 && isPrintableASCII(secret) {
					for i, c := range []byte(secret) {
						params.Secret[i] = c
					}
					break
				}
			}
		}
	}
	if params.Secret == [16]byte{} {
		for _, m := range rxString16Backtick.FindAllStringSubmatch(iframeJS, -1) {
			if len(m) >= 2 {
				secret := m[1]
				if len(secret) == 16 && isPrintableASCII(secret) {
					for i, c := range []byte(secret) {
						params.Secret[i] = c
					}
					break
				}
			}
		}
	}
}

// extractRunnerAndEncoder uses AST analysis to find the program runner, the
// encoder function name, and the initial VM program. These don't have
// reliable regex counterparts because they depend on AST structure.
func extractRunnerAndEncoder(src string, params *EncoderParams) {
	defer func() {
		// goja can panic on malformed input; recover and continue.
		_ = recover()
	}()

	prog, err := parseJS(src)
	if err != nil {
		// Fall back to regex for the runner.
		extractRunnerViaRegex(src, params)
		return
	}

	// Step 1: Find the program runner installation.
	runner := findRunner(prog)
	if runner != nil {
		params.RunnerName = runner.Name
		params.RunFunc = runner.RunFunc
		params.VMClass = runner.VMClass
		params.InitialPC = runner.InitialPC
		params.InitialKey = runner.InitialKey
	}

	// Step 2: Find calls to the runner with a literal string argument → initial VM program.
	if runner != nil {
		if progStr := findRunnerCallWithLiteral(prog, runner.Name); progStr != "" {
			params.InitialProgram = progStr
		}
	}

	// Step 3: Find the encoder (the function whose result is passed to send()).
	encoderName := findEncoder(prog)
	if encoderName != "" {
		params.Encoder = encoderName
	}

	// Step 4: Find the key-transform name (unbound global called from the encoder).
	if encoderName != "" {
		if kt := findKeyTransform(prog, encoderName); kt != "" {
			params.KeyTransform = kt
		}
	}

	// If AST extraction didn't find a runner, try regex.
	if params.RunnerName == "" {
		extractRunnerViaRegex(src, params)
	}
}

// extractRunnerViaRegex is a regex fallback for finding the program runner.
func extractRunnerViaRegex(src string, params *EncoderParams) {
	if params.RunnerName != "" {
		return
	}
	m := rxRunnerInstall.FindStringSubmatch(src)
	if len(m) >= 6 {
		params.RunnerName = m[1]
		params.RunFunc = m[2]
		params.VMClass = m[3]
		fmt.Sscanf(m[4], "%f", &params.InitialPC)
		fmt.Sscanf(m[5], "%f", &params.InitialKey)
	}
}

// tryModulus parses a hex string and returns a *big.Int if it's a 1024-bit modulus.
func tryModulus(hexStr string) *big.Int {
	mod, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		return nil
	}
	if mod.BitLen() == 0 {
		return nil
	}
	// 1024-bit modulus → 128 bytes. (BitLen() may be 1024 or 1025 if the
	// leading byte is 0x00; (BitLen()+7)/8 should equal 128.)
	if (mod.BitLen()+7)/8 != 128 {
		return nil
	}
	return mod
}

// isDistinctASCII checks whether s consists of 64 distinct ASCII characters.
func isDistinctASCII(s string) bool {
	if len(s) != 64 {
		return false
	}
	seen := make(map[byte]bool)
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
		if seen[s[i]] {
			return false
		}
		seen[s[i]] = true
	}
	return true
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

// ModulusHex returns the RSA modulus as a hex string.
func (p *EncoderParams) ModulusHex() string {
	if p.Modulus == nil {
		return ""
	}
	return hex.EncodeToString(p.Modulus.Bytes())
}

// String returns a description of the encoder parameters.
func (p *EncoderParams) String() string {
	modulusBits := 0
	if p.Modulus != nil {
		modulusBits = p.Modulus.BitLen()
	}
	hasSecret := p.Secret != [16]byte{}
	return fmt.Sprintf("EncoderParams{alphabet: %d chars, modulus: %d bits, secret: %t, keyTransform: %q, encoder: %q, runner: %q, initialProgram: %d bytes}",
		len(p.Alphabet), modulusBits, hasSecret, p.KeyTransform, p.Encoder, p.RunnerName, len(p.InitialProgram))
}

// HasAllParams reports whether all required parameters were found.
func (p *EncoderParams) HasAllParams() bool {
	return p.Modulus != nil && p.Alphabet != "" && p.Secret != [16]byte{}
}

// HasCoreParams reports whether the core parameters (modulus + alphabet) were
// found. The secret may require VM execution to extract.
func (p *EncoderParams) HasCoreParams() bool {
	return p.Modulus != nil && p.Alphabet != ""
}

// FindAlphabetCandidates finds all string literals in the source that could be
// base64 alphabets.
func FindAlphabetCandidates(source string) []string {
	var candidates []string
	for _, m := range rxString64.FindAllStringSubmatch(source, -1) {
		if len(m) >= 2 {
			candidate := m[1]
			if len(candidate) >= 64 {
				candidate = candidate[:64]
			}
			if isDistinctASCII(candidate) {
				candidates = append(candidates, candidate)
			}
		}
	}
	return candidates
}

// FindModulusCandidates finds all BigInt("0x...") calls in the source.
func FindModulusCandidates(source string) []*big.Int {
	var moduli []*big.Int
	for _, m := range rxBigInt.FindAllStringSubmatch(source, -1) {
		if len(m) >= 2 {
			modulus, ok := new(big.Int).SetString(m[1], 16)
			if ok && modulus.BitLen() > 0 {
				moduli = append(moduli, modulus)
			}
		}
	}
	return moduli
}

// FindSecretCandidates finds all 16-character string literals in the source.
func FindSecretCandidates(source string) []string {
	var candidates []string
	for _, m := range rxString16.FindAllStringSubmatch(source, -1) {
		if len(m) >= 2 && len(m[1]) == 16 && isPrintableASCII(m[1]) {
			candidates = append(candidates, m[1])
		}
	}
	return candidates
}

// EncodeModulusHex encodes a big.Int as a 0x-prefixed hex string.
func EncodeModulusHex(n *big.Int) string {
	return "0x" + strings.ToLower(hex.EncodeToString(n.Bytes()))
}

// ---- AST-based extraction helpers ----

// runnerInfo describes a program runner installation.
type runnerInfo struct {
	Name       string // the property name on the global object
	RunFunc    string // the run function name
	VMClass    string // the VM class name
	InitialPC  float64
	InitialKey float64
}

// parseJS parses JavaScript source and returns the AST program.
func parseJS(src string) (*ast.Program, error) {
	// Use goja's parser directly via the ast package's Parse function.
	// goja exposes parser.Parse through the main package; we use it indirectly.
	return parseJSViaGoja(src)
}

// findRunner searches the AST for the program runner installation:
//
//	<global>.<name> = function(p){ return <run>(new <Class>(p), pc, key, []); }
//
// This mirrors cfsolve's vm::extract::Runner::installed_by.
func findRunner(prog *ast.Program) *runnerInfo {
	if prog == nil {
		return nil
	}
	var found *runnerInfo
	walkProgram(prog, func(node ast.Node) bool {
		if found != nil {
			return false
		}
		ae, ok := node.(*ast.AssignExpression)
		if !ok {
			return true
		}
		// Left must be a member expression: <global>.<name> or <global>["name"].
		name := memberName(ae.Left)
		if name == "" {
			return true
		}
		// Right must be a function literal.
		fe, ok := ae.Right.(*ast.FunctionLiteral)
		if !ok || fe.Body == nil || len(fe.Body.List) == 0 {
			return true
		}
		// Body must have a return statement (after optional declarations).
		var ret *ast.ReturnStatement
		for _, stmt := range fe.Body.List {
			if r, ok := stmt.(*ast.ReturnStatement); ok {
				ret = r
				break
			}
		}
		if ret == nil || ret.Argument == nil {
			return true
		}
		// Return argument must be a call expression: <run>(new <Class>(p), pc, key, [])
		ce, ok := ret.Argument.(*ast.CallExpression)
		if !ok {
			return true
		}
		// Callee: <run> identifier.
		runIdent, ok := ce.Callee.(*ast.Identifier)
		if !ok {
			return true
		}
		if len(ce.ArgumentList) < 4 {
			return true
		}
		// Among the arguments, find:
		//   - A NewExpression (the VM class instance)
		//   - Two consecutive numeric expressions (pc, key) — these may be
		//     computed XOR/NOT expressions like 65382^(31090^~-19635)^51878
		//     that our deobfuscation didn't fully fold.
		//   - An empty array literal (the register file) — optional.
		var ne *ast.NewExpression
		var classIdent *ast.Identifier
		var pcVal, keyVal float64
		var pcFound, keyFound bool
		for i, arg := range ce.ArgumentList {
			if e, ok := arg.(*ast.NewExpression); ok && ne == nil {
				ne = e
				if id, ok := e.Callee.(*ast.Identifier); ok {
					classIdent = id
				}
			}
			// Try to evaluate this argument as a constant number.
			if v, ok := evalConstInt(arg); ok {
				if !pcFound {
					pcVal = v
					pcFound = true
				} else if !keyFound {
					keyVal = v
					keyFound = true
				}
			}
			_ = i
		}
		if ne == nil || classIdent == nil || !pcFound || !keyFound {
			return true
		}
		found = &runnerInfo{
			Name:       name,
			RunFunc:    string(runIdent.Name),
			VMClass:    string(classIdent.Name),
			InitialPC:  pcVal,
			InitialKey: keyVal,
		}
		return false
	})
	return found
}

// findRunnerCallWithLiteral searches for calls to the runner with a literal
// string argument. Returns the first such string.
func findRunnerCallWithLiteral(prog *ast.Program, runnerName string) string {
	if prog == nil || runnerName == "" {
		return ""
	}
	var result string
	walkProgram(prog, func(node ast.Node) bool {
		if result != "" {
			return false
		}
		ce, ok := node.(*ast.CallExpression)
		if !ok {
			return true
		}
		if !isRunnerCall(ce, runnerName) {
			return true
		}
		if len(ce.ArgumentList) == 0 {
			return true
		}
		// First argument must be a string literal.
		if sl, ok := ce.ArgumentList[0].(*ast.StringLiteral); ok {
			result = string(sl.Value)
			return false
		}
		// Or a template literal with one element and no expressions.
		if tl, ok := ce.ArgumentList[0].(*ast.TemplateLiteral); ok {
			if len(tl.Expressions) == 0 && len(tl.Elements) == 1 {
				result = tl.Elements[0].Literal
				return false
			}
		}
		return true
	})
	return result
}

// isRunnerCall checks if a call expression calls the named runner.
func isRunnerCall(ce *ast.CallExpression, name string) bool {
	if id, ok := ce.Callee.(*ast.Identifier); ok {
		return string(id.Name) == name
	}
	return memberName(ce.Callee) == name
}

// findEncoder finds the encoder function name by locating send() calls and
// extracting the function that produced the argument.
//
//	Pattern: <obj>.send(<encoder>(...)) or <obj>["send"](<encoder>(...))
func findEncoder(prog *ast.Program) string {
	if prog == nil {
		return ""
	}
	var encoder string
	walkProgram(prog, func(node ast.Node) bool {
		if encoder != "" {
			return false
		}
		ce, ok := node.(*ast.CallExpression)
		if !ok {
			return true
		}
		// Callee must be a member expression with name "send".
		if memberName(ce.Callee) != "send" {
			return true
		}
		// First argument must be a call expression.
		if len(ce.ArgumentList) == 0 {
			return true
		}
		argCall, ok := ce.ArgumentList[0].(*ast.CallExpression)
		if !ok {
			return true
		}
		// The encoder is the callee of the argument call.
		if id, ok := argCall.Callee.(*ast.Identifier); ok {
			encoder = string(id.Name)
			return false
		}
		return true
	})
	return encoder
}

// findKeyTransform finds the unbound global function called from the encoder's
// definition. This mirrors cfsolve's key_transform function in program.rs.
func findKeyTransform(prog *ast.Program, encoderName string) string {
	if prog == nil || encoderName == "" {
		return ""
	}
	// Find the encoder's assignment and collect all global function calls
	// in its definition body.
	declared := collectDeclaredNames(prog)
	called := make(map[string]int)
	findEncoderCalls(prog, encoderName, called)
	// Filter: the key transform is a global that's not declared and not
	// a known JS builtin.
	builtins := map[string]bool{
		"Number": true, "BigInt": true, "String": true, "Boolean": true,
		"Array": true, "Object": true, "Math": true, "Date": true,
		"JSON": true, "parseInt": true, "parseFloat": true,
		"isNaN": true, "isFinite": true, "undefined": true,
		"Symbol": true, "Promise": true, "Proxy": true, "Reflect": true,
		"Map": true, "Set": true, "WeakMap": true, "WeakSet": true,
		"Error": true, "TypeError": true, "RangeError": true,
		"ArrayBuffer": true, "DataView": true,
		"Uint8Array": true, "Uint16Array": true, "Uint32Array": true,
		"Int8Array": true, "Int16Array": true, "Int32Array": true,
		"Float32Array": true, "Float64Array": true,
		"encodeURI": true, "encodeURIComponent": true,
		"decodeURI": true, "decodeURIComponent": true,
		"eval": true, "RegExp": true,
	}
	for name := range called {
		if declared[name] {
			continue
		}
		if builtins[name] {
			continue
		}
		return name
	}
	return ""
}

// collectDeclaredNames returns a set of all names declared at any scope in
// the program. This is used to filter global function calls in the encoder.
func collectDeclaredNames(prog *ast.Program) map[string]bool {
	declared := make(map[string]bool)
	walkProgram(prog, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.FunctionLiteral:
			if n.Name != nil && n.Name.Name != "" {
				declared[string(n.Name.Name)] = true
			}
		case *ast.VariableStatement:
			for _, expr := range n.List {
				if id, ok := expr.Target.(*ast.Identifier); ok {
					declared[string(id.Name)] = true
				}
			}
		case *ast.LexicalDeclaration:
			for _, expr := range n.List {
				if id, ok := expr.Target.(*ast.Identifier); ok {
					declared[string(id.Name)] = true
				}
			}
		case *ast.FunctionDeclaration:
			if n.Function != nil && n.Function.Name != nil && n.Function.Name.Name != "" {
				declared[string(n.Function.Name.Name)] = true
			}
		}
		return true
	})
	return declared
}

// findEncoderCalls collects all global function calls within the encoder's
// definition body.
func findEncoderCalls(prog *ast.Program, encoderName string, calls map[string]int) {
	walkProgram(prog, func(node ast.Node) bool {
		// Look for assignments to the encoder: <encoderName> = function(...){...}
		ae, ok := node.(*ast.AssignExpression)
		if !ok {
			return true
		}
		id, ok := ae.Left.(*ast.Identifier)
		if !ok || string(id.Name) != encoderName {
			return true
		}
		// Right side should be a function literal.
		fe, ok := ae.Right.(*ast.FunctionLiteral)
		if !ok || fe.Body == nil {
			return true
		}
		// Walk the body and collect all global function calls.
		for _, stmt := range fe.Body.List {
			walkStatement(stmt, func(n ast.Node) bool {
				if ce, ok := n.(*ast.CallExpression); ok {
					if id, ok := ce.Callee.(*ast.Identifier); ok {
						calls[string(id.Name)]++
					}
				}
				return true
			})
		}
		return false
	})
}

// memberName returns the property name of a member expression, either from
// an identifier (obj.prop) or a string literal (obj["prop"]). Also handles
// the lazy-init pattern obj[VAR||(VAR=`prop`)] which Cloudflare uses
// extensively.
func memberName(expr ast.Expression) string {
	if expr == nil {
		return ""
	}
	switch e := expr.(type) {
	case *ast.DotExpression:
		return string(e.Identifier.Name)
	case *ast.BracketExpression:
		return staticStrFromExpr(e.Member)
	}
	return ""
}

// staticStrFromExpr extracts a static string from an expression that's either:
//   - a string literal "foo" or 'foo'
//   - a template literal `foo` with no expressions
//   - a lazy-init expression VAR||(VAR=`foo`) or VAR||(VAR="foo")
//
// Cloudflare uses the lazy-init pattern extensively to hide constant strings.
func staticStrFromExpr(expr ast.Expression) string {
	if expr == nil {
		return ""
	}
	switch e := expr.(type) {
	case *ast.StringLiteral:
		return string(e.Value)
	case *ast.TemplateLiteral:
		if len(e.Expressions) == 0 && len(e.Elements) == 1 {
			return e.Elements[0].Literal
		}
	case *ast.BinaryExpression:
		// VAR || (VAR = "string") — lazy-init pattern.
		if e.Operator == token.LOGICAL_OR {
			if ae, ok := e.Right.(*ast.AssignExpression); ok {
				return staticStrFromExpr(ae.Right)
			}
		}
	case *ast.AssignExpression:
		// (VAR = "string") — bare assignment.
		return staticStrFromExpr(e.Right)
	}
	return ""
}

// walkProgram walks the AST starting from the program node, calling fn for
// each node. If fn returns false, walking stops.
func walkProgram(prog *ast.Program, fn func(ast.Node) bool) {
	if prog == nil {
		return
	}
	for _, stmt := range prog.Body {
		walkStatement(stmt, fn)
	}
}

// walkStatement walks a statement (or expression) and its children.
func walkStatement(stmt ast.Statement, fn func(ast.Node) bool) {
	if stmt == nil {
		return
	}
	walkNode(stmt, fn)
}

// walkNode walks a node and its children.
func walkNode(node ast.Node, fn func(ast.Node) bool) {
	if node == nil {
		return
	}
	if !fn(node) {
		return
	}
	switch n := node.(type) {
	case *ast.Program:
		for _, stmt := range n.Body {
			walkNode(stmt, fn)
		}
	case *ast.ExpressionStatement:
		walkNode(n.Expression, fn)
	case *ast.AssignExpression:
		walkNode(n.Left, fn)
		walkNode(n.Right, fn)
	case *ast.BinaryExpression:
		walkNode(n.Left, fn)
		walkNode(n.Right, fn)
	case *ast.CallExpression:
		walkNode(n.Callee, fn)
		for _, arg := range n.ArgumentList {
			walkNode(arg, fn)
		}
	case *ast.NewExpression:
		walkNode(n.Callee, fn)
		for _, arg := range n.ArgumentList {
			walkNode(arg, fn)
		}
	case *ast.DotExpression:
		walkNode(n.Left, fn)
	case *ast.BracketExpression:
		walkNode(n.Left, fn)
		walkNode(n.Member, fn)
	case *ast.FunctionLiteral:
		if n.Body != nil {
			for _, stmt := range n.Body.List {
				walkNode(stmt, fn)
			}
		}
	case *ast.VariableStatement:
		for _, expr := range n.List {
			if expr.Target != nil {
				walkNode(expr.Target, fn)
			}
			if expr.Initializer != nil {
				walkNode(expr.Initializer, fn)
			}
		}
	case *ast.LexicalDeclaration:
		for _, expr := range n.List {
			if expr.Target != nil {
				walkNode(expr.Target, fn)
			}
			if expr.Initializer != nil {
				walkNode(expr.Initializer, fn)
			}
		}
	case *ast.ReturnStatement:
		if n.Argument != nil {
			walkNode(n.Argument, fn)
		}
	case *ast.BlockStatement:
		for _, stmt := range n.List {
			walkNode(stmt, fn)
		}
	case *ast.IfStatement:
		walkNode(n.Test, fn)
		walkNode(n.Consequent, fn)
		if n.Alternate != nil {
			walkNode(n.Alternate, fn)
		}
	case *ast.ForStatement:
		if n.Initializer != nil {
			walkNode(n.Initializer, fn)
		}
		if n.Test != nil {
			walkNode(n.Test, fn)
		}
		if n.Update != nil {
			walkNode(n.Update, fn)
		}
		walkNode(n.Body, fn)
	case *ast.WhileStatement:
		walkNode(n.Test, fn)
		walkNode(n.Body, fn)
	case *ast.DoWhileStatement:
		walkNode(n.Body, fn)
		walkNode(n.Test, fn)
	case *ast.TryStatement:
		walkNode(n.Body, fn)
		if n.Catch != nil {
			walkNode(n.Catch, fn)
		}
		if n.Finally != nil {
			walkNode(n.Finally, fn)
		}
	case *ast.SwitchStatement:
		walkNode(n.Discriminant, fn)
		for _, sc := range n.Body {
			walkNode(sc, fn)
		}
	case *ast.CaseStatement:
		if n.Test != nil {
			walkNode(n.Test, fn)
		}
		for _, s := range n.Consequent {
			walkNode(s, fn)
		}
	case *ast.ConditionalExpression:
		walkNode(n.Test, fn)
		walkNode(n.Consequent, fn)
		walkNode(n.Alternate, fn)
	case *ast.SequenceExpression:
		for _, e := range n.Sequence {
			walkNode(e, fn)
		}
	case *ast.UnaryExpression:
		walkNode(n.Operand, fn)
	case *ast.FunctionDeclaration:
		walkNode(n.Function, fn)
	case *ast.ForInStatement:
		walkNode(n.Into, fn)
		walkNode(n.Source, fn)
		walkNode(n.Body, fn)
	case *ast.ForOfStatement:
		walkNode(n.Into, fn)
		walkNode(n.Source, fn)
		walkNode(n.Body, fn)
	case *ast.ThrowStatement:
		walkNode(n.Argument, fn)
	case *ast.LabelledStatement:
		walkNode(n.Statement, fn)
	}
}
