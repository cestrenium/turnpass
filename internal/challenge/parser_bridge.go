// Package challenge - goja parser bridge.
package challenge

import (
	"math"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"
)

// parseJSViaGoja parses JavaScript source using goja's parser and returns
// the AST program.
func parseJSViaGoja(src string) (*ast.Program, error) {
	return parser.ParseFile(nil, "", src, 0)
}

// numberLiteralToFloat64 converts a goja NumberLiteral's Value (interface{})
// to float64. Goja uses int64 for integer literals and float64 for floats.
func numberLiteralToFloat64(n *ast.NumberLiteral) float64 {
	if n == nil {
		return 0
	}
	switch v := n.Value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int64:
		return float64(v)
	case int:
		return float64(v)
	case int32:
		return float64(v)
	}
	return 0
}

// evalConstInt tries to evaluate an AST expression as a constant integer.
// It handles numeric literals and simple bitwise/arithmetic expressions
// (XOR, OR, AND, NOT, addition, subtraction, multiplication, shifts).
// This is needed because Cloudflare uses computed expressions like
// 65382^(31090^~-19635)^51878 for numeric constants that our deobfuscation
// pipeline may not have fully folded.
//
// All operations are performed as int32 (JavaScript bitwise semantics).
func evalConstInt(expr ast.Expression) (float64, bool) {
	switch e := expr.(type) {
	case *ast.NumberLiteral:
		return numberLiteralToFloat64(e), true
	case *ast.UnaryExpression:
		v, ok := evalConstInt(e.Operand)
		if !ok {
			return 0, false
		}
		switch e.Operator {
		case token.MINUS:
			return -v, true
		case token.PLUS:
			return v, true
		case token.BITWISE_NOT:
			// Bitwise NOT: ~x = -(x+1)
			return float64(^toInt32(v)), true
		}
		return 0, false
	case *ast.BinaryExpression:
		l, ok1 := evalConstInt(e.Left)
		r, ok2 := evalConstInt(e.Right)
		if !ok1 || !ok2 {
			return 0, false
		}
		switch e.Operator {
		case token.PLUS:
			return l + r, true
		case token.MINUS:
			return l - r, true
		case token.MULTIPLY:
			return l * r, true
		case token.SLASH:
			if r == 0 {
				return 0, false
			}
			return l / r, true
		case token.REMAINDER:
			if r == 0 {
				return 0, false
			}
			return math.Mod(l, r), true
		case token.AND:
			return float64(toInt32(l) & toInt32(r)), true
		case token.OR:
			return float64(toInt32(l) | toInt32(r)), true
		case token.EXCLUSIVE_OR:
			return float64(toInt32(l) ^ toInt32(r)), true
		case token.SHIFT_LEFT:
			return float64(toInt32(l) << (uint32(toInt32(r)) & 31)), true
		case token.SHIFT_RIGHT:
			return float64(toInt32(l) >> (uint32(toInt32(r)) & 31)), true
		case token.UNSIGNED_SHIFT_RIGHT:
			return float64(uint32(toInt32(l)) >> (uint32(toInt32(r)) & 31)), true
		}
		return 0, false
	}
	return 0, false
}

// toInt32 converts a float64 to int32 using JavaScript's ToInt32 semantics.
func toInt32(v float64) int32 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	n := math.Trunc(v)
	n = math.Mod(n, 4294967296) // 2^32
	if n < 0 {
		n += 4294967296
	}
	if n >= 2147483648 {
		n -= 4294967296
	}
	return int32(n)
}
