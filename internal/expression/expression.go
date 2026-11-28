// Package expression evaluates Cloudflare challenge payload template
// field expressions against _cf_chl_opt options and window globals.
// Mirrors cfsolve's src/challenge/expression.rs.
package expression

import (
	"fmt"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/token"

	"github.com/cestrenium/turnpass/internal/js"
)

type Options map[string]js.Value
type Globals map[string]js.Value

type Evaluator struct {
	script  *ast.Program
	options Options
	globals Globals
}

func New(script *ast.Program, options Options, globals Globals) *Evaluator {
	if options == nil {
		options = make(Options)
	}
	if globals == nil {
		globals = make(Globals)
	}
	return &Evaluator{script: script, options: options, globals: globals}
}

func (e *Evaluator) Evaluate(expr ast.Expression) (js.Value, error) {
	switch ex := expr.(type) {
	case *ast.StringLiteral:
		return js.String(string(ex.Value)), nil
	case *ast.TemplateLiteral:
		if len(ex.Expressions) == 0 && len(ex.Elements) == 1 {
			return js.String(ex.Elements[0].Literal), nil
		}
		var result string
		for i, elem := range ex.Elements {
			result += elem.Literal
			if i < len(ex.Expressions) {
				val, err := e.Evaluate(ex.Expressions[i])
				if err != nil {
					return nil, err
				}
				result += js.ToString(val)
			}
		}
		return js.String(result), nil
	case *ast.NumberLiteral:
		return js.Number(numToFloat(ex)), nil
	case *ast.BooleanLiteral:
		return js.Bool(ex.Value), nil
	case *ast.NullLiteral:
		return js.Null{}, nil
	case *ast.Identifier:
		name := string(ex.Name)
		if name == "undefined" {
			return nil, nil
		}
		if v, ok := e.globals[name]; ok {
			return v, nil
		}
		return nil, nil
	case *ast.BinaryExpression:
		return e.evalBinary(ex)
	case *ast.UnaryExpression:
		if ex.Operator == token.NOT {
			val, err := e.Evaluate(ex.Operand)
			if err != nil {
				return nil, err
			}
			return js.Bool(!js.Truthy(val)), nil
		}
		return nil, fmt.Errorf("unsupported unary: %v", ex.Operator)
	case *ast.DotExpression:
		key := string(ex.Identifier.Name)
		if e.isOptions(ex.Left) {
			if v, ok := e.options[key]; ok {
				return v, nil
			}
			return nil, nil
		}
		if _, ok := ex.Left.(*ast.Identifier); ok {
			if v, ok := e.globals[key]; ok {
				return v, nil
			}
		}
		objVal, err := e.Evaluate(ex.Left)
		if err != nil {
			return nil, err
		}
		if obj, ok := objVal.(js.Object); ok {
			if v, ok := obj[key]; ok {
				return v, nil
			}
		}
		return nil, nil
	case *ast.BracketExpression:
		key := staticStr(ex.Member)
		if key == "" {
			return nil, fmt.Errorf("unsupported computed property")
		}
		if e.isOptions(ex.Left) {
			if v, ok := e.options[key]; ok {
				return v, nil
			}
			return nil, nil
		}
		if _, ok := ex.Left.(*ast.Identifier); ok {
			if v, ok := e.globals[key]; ok {
				return v, nil
			}
		}
		return nil, nil
	case *ast.CallExpression:
		return e.evalCall(ex)
	case *ast.ObjectLiteral:
		obj := make(js.Object)
		for _, prop := range ex.Value {
			if kp, ok := prop.(*ast.PropertyKeyed); ok {
				key := propKey(kp.Key)
				if key == "" {
					continue
				}
				val, err := e.Evaluate(kp.Value)
				if err != nil {
					continue
				}
				if val != nil {
					obj[key] = val
				}
			}
		}
		return obj, nil
	case *ast.ArrayLiteral:
		arr := make(js.Array, 0, len(ex.Value))
		for _, elem := range ex.Value {
			if _, ok := elem.(*ast.SpreadElement); ok {
				continue
			}
			val, _ := e.Evaluate(elem)
			if val == nil {
				arr = append(arr, js.Null{})
			} else {
				arr = append(arr, val)
			}
		}
		return arr, nil
	}
	return nil, fmt.Errorf("unsupported expression: %T", expr)
}

func (e *Evaluator) evalBinary(ex *ast.BinaryExpression) (js.Value, error) {
	left, err := e.Evaluate(ex.Left)
	if err != nil {
		return nil, err
	}
	right, err := e.Evaluate(ex.Right)
	if err != nil {
		return nil, err
	}
	switch ex.Operator {
	case token.PLUS:
		if isTextual(left) || isTextual(right) {
			return js.String(js.ToString(left) + js.ToString(right)), nil
		}
		return js.Number(js.ToNumber(left) + js.ToNumber(right)), nil
	case token.MINUS:
		return js.Number(js.ToNumber(left) - js.ToNumber(right)), nil
	case token.MULTIPLY:
		return js.Number(js.ToNumber(left) * js.ToNumber(right)), nil
	case token.SLASH:
		r := js.ToNumber(right)
		if r == 0 {
			return js.Null{}, nil
		}
		return js.Number(js.ToNumber(left) / r), nil
	}
	return nil, fmt.Errorf("unsupported binary: %v", ex.Operator)
}

func (e *Evaluator) evalCall(ex *ast.CallExpression) (js.Value, error) {
	if me, ok := ex.Callee.(*ast.DotExpression); ok {
		if id, ok := me.Left.(*ast.Identifier); ok && string(id.Name) == "JSON" && string(me.Identifier.Name) == "stringify" {
			if len(ex.ArgumentList) >= 1 {
				val, err := e.Evaluate(ex.ArgumentList[0])
				if err != nil {
					return nil, err
				}
				if val == nil {
					return nil, nil
				}
				return js.String(js.ToString(val)), nil
			}
		}
	}
	if me, ok := ex.Callee.(*ast.DotExpression); ok {
		if _, ok := me.Left.(*ast.Identifier); ok && len(ex.ArgumentList) == 0 {
			key := string(me.Identifier.Name)
			if v, ok := e.globals[key]; ok {
				return v, nil
			}
		}
	}
	if be, ok := ex.Callee.(*ast.BracketExpression); ok {
		if _, ok := be.Left.(*ast.Identifier); ok && len(ex.ArgumentList) == 0 {
			key := staticStr(be.Member)
			if key != "" {
				if v, ok := e.globals[key]; ok {
					return v, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("unsupported call")
}

func (e *Evaluator) isOptions(expr ast.Expression) bool {
	if me, ok := expr.(*ast.DotExpression); ok {
		return string(me.Identifier.Name) == "_cf_chl_opt"
	}
	if be, ok := expr.(*ast.BracketExpression); ok {
		return staticStr(be.Member) == "_cf_chl_opt"
	}
	if id, ok := expr.(*ast.Identifier); ok {
		return string(id.Name) == "_cf_chl_opt"
	}
	return false
}

func staticStr(expr ast.Expression) string {
	if expr == nil {
		return ""
	}
	switch v := expr.(type) {
	case *ast.StringLiteral:
		return string(v.Value)
	case *ast.TemplateLiteral:
		if len(v.Expressions) == 0 && len(v.Elements) == 1 {
			return v.Elements[0].Literal
		}
	}
	return ""
}

func propKey(expr ast.Expression) string {
	if id, ok := expr.(*ast.Identifier); ok {
		return string(id.Name)
	}
	return staticStr(expr)
}

func isTextual(v js.Value) bool {
	switch v.(type) {
	case js.String, js.Array, js.Object:
		return true
	}
	return false
}

func numToFloat(n *ast.NumberLiteral) float64 {
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
