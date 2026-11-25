// Package challenge - goja parser bridge.
package challenge

import (
	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
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
