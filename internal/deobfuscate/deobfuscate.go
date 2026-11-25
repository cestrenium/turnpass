// Package deobfuscate implements the full deobfuscation pipeline for
// Cloudflare challenge orchestrator scripts.
package deobfuscate

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"
)

// Deobfuscator holds the state of the deobfuscation pipeline.
type Deobfuscator struct {
	Source            string
	XORKeys           map[string]int64
	StringCache       map[string]string
	StringDecoderName string
}

// New creates a Deobfuscator for the given source.
func New(source string) *Deobfuscator {
	return &Deobfuscator{
		Source:      source,
		XORKeys:     make(map[string]int64),
		StringCache: make(map[string]string),
	}
}

// Deobfuscate runs the full pipeline and returns the deobfuscated source.
func (d *Deobfuscator) Deobfuscate() (string, error) {
	d.resolveXORKeys()
	result := d.foldConstants(d.Source)
	d.findStringDecoder(result)
	result = d.decodeStringCalls(result)
	result = d.replaceXORAccesses(result)
	return result, nil
}

// resolveXORKeys finds _0xNNNN = (a=>a).length + N and resolves them.
func (d *Deobfuscator) resolveXORKeys() {
	rx := regexp.MustCompile(`(_0x[0-9a-f]+)\s*=\s*\(a=>a\)\.length\s*\+\s*(\d+)`)
	for _, m := range rx.FindAllStringSubmatch(d.Source, -1) {
		if len(m) >= 3 {
			n, err := strconv.ParseInt(m[2], 10, 64)
			if err == nil {
				d.XORKeys[m[1]] = n + 1
			}
		}
	}
}

// foldConstants folds XOR chains and (n|0) patterns.
func (d *Deobfuscator) foldConstants(source string) string {
	result := source

	// Fold XOR chains of pure numbers: 10299^(46025^221581)^57172
	rxChain := regexp.MustCompile(`\b(\d+(?:\s*\^\s*\d+)+)\b`)
	result = rxChain.ReplaceAllStringFunc(result, func(s string) string {
		n := d.evalXORChain(s)
		if n >= 0 {
			return strconv.FormatInt(n, 10)
		}
		return s
	})

	// Fold (n|0) to n
	rxOrZero := regexp.MustCompile(`\((\d+)\|0\)`)
	result = rxOrZero.ReplaceAllString(result, "$1")

	return result
}

func (d *Deobfuscator) evalXORChain(s string) int64 {
	parts := strings.Split(s, "^")
	if len(parts) < 2 {
		return -1
	}
	result, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return -1
	}
	for _, p := range parts[1:] {
		n, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64)
		if err != nil {
			return -1
		}
		result ^= n
	}
	return result
}

// findStringDecoder finds the name of the string decoder function.
func (d *Deobfuscator) findStringDecoder(source string) {
	for _, name := range []string{"aa", "a0", "a1", "a2", "a3", "a4", "a5", "ab", "ac", "ad"} {
		if regexp.MustCompile(regexp.QuoteMeta(name) + `\(\x60`).MatchString(source) {
			d.StringDecoderName = name
			return
		}
	}
}

// decodeStringCalls finds and decodes all string decoder calls.
func (d *Deobfuscator) decodeStringCalls(source string) string {
	if d.StringDecoderName == "" {
		return source
	}
	pattern := regexp.MustCompile(regexp.QuoteMeta(d.StringDecoderName) + `\(\x60([^\x60]+)\x60\)`)
	return pattern.ReplaceAllStringFunc(source, func(s string) string {
		m := pattern.FindStringSubmatch(s)
		if len(m) < 2 {
			return s
		}
		encoded := m[1]
		if decoded, ok := d.StringCache[encoded]; ok {
			escaped := strings.ReplaceAll(decoded, "`", "\\`")
			return "`" + escaped + "`"
		}
		decoded := DecodeAaString(encoded)
		if decoded != "" {
			d.StringCache[encoded] = decoded
			escaped := strings.ReplaceAll(decoded, "`", "\\`")
			return "`" + escaped + "`"
		}
		return s
	})
}

// replaceXORAccesses replaces obj[N ^ _0xKEY] with obj[resolvedN].
func (d *Deobfuscator) replaceXORAccesses(source string) string {
	result := source
	for varName, keyVal := range d.XORKeys {
		// NUMBER ^ _0xKEY
		pattern := regexp.MustCompile(`(\d+)\s*\^\s*` + regexp.QuoteMeta(varName))
		result = pattern.ReplaceAllStringFunc(result, func(s string) string {
			m := pattern.FindStringSubmatch(s)
			if len(m) < 2 {
				return s
			}
			n, err := strconv.ParseInt(m[1], 10, 64)
			if err != nil {
				return s
			}
			return strconv.FormatInt(n^keyVal, 10)
		})
		// _0xKEY ^ NUMBER
		pattern2 := regexp.MustCompile(regexp.QuoteMeta(varName) + `\s*\^\s*(\d+)`)
		result = pattern2.ReplaceAllStringFunc(result, func(s string) string {
			m := pattern2.FindStringSubmatch(s)
			if len(m) < 2 {
				return s
			}
			n, err := strconv.ParseInt(m[1], 10, 64)
			if err != nil {
				return s
			}
			return strconv.FormatInt(n^keyVal, 10)
		})
	}
	return result
}

// DecodeAaString decodes a string using the aa()/a0() obfuscation.
// Base64 decode, then XOR with rolling 16-bit key starting at 8185.
func DecodeAaString(encoded string) string {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	key := uint16(8185)
	var result []uint16
	var buffer []uint16

	for i := 0; i < len(decoded); {
		key = (key<<8 | key>>8) & 0xFFFF
		if i >= len(decoded) {
			break
		}
		h := uint16(decoded[i]) ^ (key >> 8)
		i++
		if h == 255 {
			key = (key<<8 | key>>8) & 0xFFFF
			if i >= len(decoded) {
				break
			}
			h = uint16(decoded[i]) ^ (key >> 8)
			i++
			key = (key<<8 | key>>8) & 0xFFFF
			if i >= len(decoded) {
				break
			}
			h |= (uint16(decoded[i]) ^ (key >> 8)) << 8
			i++
		}
		buffer = append(buffer, h)
		if len(buffer) == 128 {
			result = append(result, buffer...)
			buffer = buffer[:0]
		}
	}
	result = append(result, buffer...)

	runes := make([]rune, 0, len(result))
	for _, u := range result {
		runes = append(runes, rune(u))
	}
	return string(runes)
}

// DeobfuscateScript is the main entry point.
func DeobfuscateScript(source string) (string, error) {
	d := New(source)
	result, err := d.Deobfuscate()
	if err != nil {
		return "", err
	}
	// Verify the result is parseable (best effort).
	_, err = parser.ParseFile(nil, "", result, 0)
	if err != nil {
		return result, nil // Return text-level result even if not fully parseable.
	}
	return result, nil
}

// FoldConstantExpression evaluates a constant AST expression.
func FoldConstantExpression(expr ast.Expression) (interface{}, bool) {
	switch e := expr.(type) {
	case *ast.NumberLiteral:
		return toInt64(e.Value), true
	case *ast.StringLiteral:
		return string(e.Value), true
	case *ast.BooleanLiteral:
		return e.Value, true
	case *ast.NullLiteral:
		return nil, true
	case *ast.BinaryExpression:
		left, ok1 := FoldConstantExpression(e.Left)
		right, ok2 := FoldConstantExpression(e.Right)
		if !ok1 || !ok2 {
			return nil, false
		}
		return foldBinary(e.Operator, left, right), true
	case *ast.UnaryExpression:
		operand, ok := FoldConstantExpression(e.Operand)
		if !ok {
			return nil, false
		}
		return foldUnary(e.Operator, operand), true
	}
	return nil, false
}

func foldBinary(op token.Token, left, right interface{}) interface{} {
	ln, lok := toInt64Val(left)
	rn, rok := toInt64Val(right)
	if lok && rok {
		switch op {
		case token.PLUS:
			return ln + rn
		case token.MINUS:
			return ln - rn
		case token.MULTIPLY:
			return ln * rn
		case token.SLASH:
			if rn != 0 {
				return ln / rn
			}
		case token.REMAINDER:
			if rn != 0 {
				return ln % rn
			}
		case token.AND:
			return ln & rn
		case token.OR:
			return ln | rn
		case token.EXCLUSIVE_OR:
			return ln ^ rn
		case token.SHIFT_LEFT:
			return ln << (uint64(rn) & 63)
		case token.SHIFT_RIGHT:
			return ln >> (uint64(rn) & 63)
		case token.UNSIGNED_SHIFT_RIGHT:
			return int64(uint64(ln) >> (uint64(rn) & 63))
		case token.LESS:
			return ln < rn
		case token.GREATER:
			return ln > rn
		case token.LESS_OR_EQUAL:
			return ln <= rn
		case token.GREATER_OR_EQUAL:
			return ln >= rn
		case token.EQUAL, token.STRICT_EQUAL:
			return ln == rn
		case token.NOT_EQUAL, token.STRICT_NOT_EQUAL:
			return ln != rn
		}
	}
	if op == token.PLUS {
		if ls, ok := left.(string); ok {
			if rs, ok := right.(string); ok {
				return ls + rs
			}
		}
	}
	return nil
}

func foldUnary(op token.Token, operand interface{}) interface{} {
	n, ok := toInt64Val(operand)
	if !ok {
		return nil
	}
	switch op {
	case token.MINUS:
		return -n
	case token.NOT:
		return n == 0
	case token.BITWISE_NOT:
		return ^n
	}
	return nil
}

func toInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	case int:
		return int64(n)
	}
	return 0
}

func toInt64Val(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	}
	return 0, false
}

// Stats returns statistics about the deobfuscation.
func (d *Deobfuscator) Stats() string {
	return fmt.Sprintf("Deobfuscator{xor_keys: %d, strings_decoded: %d, decoder: %s}",
		len(d.XORKeys), len(d.StringCache), d.StringDecoderName)
}
