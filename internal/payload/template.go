// Package payload extracts and evaluates the Cloudflare challenge payload
// template from the orchestrator JavaScript.
//
// This mirrors cfsolve's src/challenge/source.rs and src/challenge/payload.rs.
// The payload template is an ObjectExpression with >20 properties where each
// property's value is an expression that reads from _cf_chl_opt. The
// orchestrator renames _cf_chl_opt properties from standard names (cH, cFPWv,
// cRay) to obfuscated _hex names at startup. We track these renames to build
// the options map, then evaluate each field expression to produce the
// plaintext JSON payload.
package payload

import (
	"fmt"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"

	"github.com/cestrenium/turnpass/internal/deobfuscate"
	"github.com/cestrenium/turnpass/internal/expression"
	"github.com/cestrenium/turnpass/internal/js"
)

// PAYLOAD_FIELDS is the minimum number of properties for a payload template.
const PAYLOAD_FIELDS = 20

// INITIAL_CHALLENGE is the prefix of the initial challenge type option value.
const INITIAL_CHALLENGE = "chl_api_"

// PAGE_CHALLENGES are challenge types used by page orchestrators.
var pageChallenges = []string{"managed", "non-interactive", "interactive"}

// TemplateField represents one field in the payload template.
type TemplateField struct {
	Name       string
	Expression ast.Expression
}

// ExtractAndBuild extracts the payload template from the orchestrator source,
// evaluates each field against the _cf_chl_opt options, and returns the
// plaintext JSON payload string.
//
// cfChlOptValues are the _cf_chl_opt values. These should include both the
// standard-name values from the challenge page HTML (cH, cFPWv, cRay, etc.)
// and the VM-extracted renamed _hex properties (from the goja sandbox).
// orchestratorJS is the raw (obfuscated) orchestrator source.
func ExtractAndBuild(orchestratorJS string, cfChlOptValues map[string]string) (string, error) {
	// Deobfuscate the source first to resolve lazy-init patterns.
	deobf, err := deobfuscate.DeobfuscateWithInlining(orchestratorJS)
	if err != nil {
		// Fall back to raw source if deobfuscation fails.
		deobf = orchestratorJS
	}

	// Parse the deobfuscated orchestrator.
	prog, err := parser.ParseFile(nil, "", deobf, 0)
	if err != nil {
		return "", fmt.Errorf("parsing orchestrator: %w", err)
	}

	// Build the options map by combining provided values with static
	// assignments from the orchestrator's bootstrap IIFE.
	options := buildOptions(prog, cfChlOptValues)

	// Find the payload template.
	template, err := findPayloadTemplate(prog, options)
	if err != nil {
		return "", fmt.Errorf("finding payload template: %w", err)
	}
	if template == nil {
		return "", fmt.Errorf("no payload template found")
	}

	// Evaluate each field.
	globals := make(expression.Globals)
	eval := expression.New(prog, expression.Options(options), globals)

	result := make(js.Object)
	for _, field := range template {
		val, err := eval.Evaluate(field.Expression)
		if err != nil {
			continue // Skip fields that can't be evaluated
		}
		if val != nil {
			result[field.Name] = val
		}
	}

	if len(result) == 0 {
		return "", fmt.Errorf("no payload fields could be evaluated")
	}

	return js.Stringify(result), nil
}

// buildOptions builds the options map by combining HTML values with
// VM-extracted options. The orchestrator's VM renames standard names
// (cH, cFPWv, etc.) to obfuscated _hex names. The VM-extracted options
// (from the goja sandbox) include these renamed properties.
// We merge both: HTML values provide the standard names, VM options
// provide the renamed _hex names.
func buildOptions(prog *ast.Program, cfChlOptValues map[string]string) expression.Options {
	options := make(expression.Options)

	// Start with standard-name values from the HTML.
	for k, v := range cfChlOptValues {
		options[k] = js.String(v)
	}

	// Also track static assignments in the orchestrator's bootstrap IIFE.
	// These include _cf_chl_opt._hexname = "challenges.cloudflare.com"
	// and _cf_chl_opt._hexname = {object} assignments.
	walkAST(prog, func(node ast.Node) bool {
		if ae, ok := node.(*ast.AssignExpression); ok {
			// Check for: _cf_chl_opt._hexname = value
			if de, ok := ae.Left.(*ast.DotExpression); ok {
				if isCfChlOpt(de.Left) {
					key := string(de.Identifier.Name)
					val := evalStatic(ae.Right, options)
					if val != nil {
						options[key] = val
					}
				}
			}
			// Check for: _cf_chl_opt['_hexname'] = value
			if be, ok := ae.Left.(*ast.BracketExpression); ok {
				if isCfChlOpt(be.Left) {
					key := staticStr(be.Member)
					if key != "" {
						val := evalStatic(ae.Right, options)
						if val != nil {
							options[key] = val
						}
					}
				}
			}
		}
		return true
	})

	return options
}

// evalStatic tries to evaluate a simple static expression to a js.Value.
// Handles string literals, numbers, booleans, null, and simple objects.
func evalStatic(expr ast.Expression, options expression.Options) js.Value {
	switch v := expr.(type) {
	case *ast.StringLiteral:
		return js.String(string(v.Value))
	case *ast.TemplateLiteral:
		if len(v.Expressions) == 0 && len(v.Elements) == 1 {
			return js.String(v.Elements[0].Literal)
		}
	case *ast.NumberLiteral:
		return js.Number(numToFloat(v))
	case *ast.BooleanLiteral:
		return js.Bool(v.Value)
	case *ast.NullLiteral:
		return js.Null{}
	case *ast.Identifier:
		if string(v.Name) == "false" {
			return js.Bool(false)
		}
		if string(v.Name) == "true" {
			return js.Bool(true)
		}
	}
	return nil
}

func numToFloat(n *ast.NumberLiteral) float64 {
	switch v := n.Value.(type) {
	case float64:
		return v
	case int64:
		return float64(v)
	case int:
		return float64(v)
	}
	return 0
}

// findPayloadTemplate finds the ObjectExpression that is the payload template.
// It must have >PAYLOAD_FIELDS properties. The challenge-type check is
// optional — if no option values match, we accept any large object.
func findPayloadTemplate(prog *ast.Program, options expression.Options) ([]TemplateField, error) {
	var best []TemplateField
	bestCount := 0

	walkAST(prog, func(node ast.Node) bool {
		obj, ok := node.(*ast.ObjectLiteral)
		if !ok {
			return true
		}
		if len(obj.Value) <= PAYLOAD_FIELDS {
			return true
		}

		var fields []TemplateField
		optionReads := 0
		for _, prop := range obj.Value {
			kp, ok := prop.(*ast.PropertyKeyed)
			if !ok {
				continue
			}
			name := propertyKey(kp.Key)
			if name == "" {
				continue
			}
			// Count how many fields read from _cf_chl_opt.
			if optionKey(kp.Value) != "" {
				optionReads++
			}
			fields = append(fields, TemplateField{
				Name:       name,
				Expression: kp.Value,
			})
		}

		// The payload template has many fields that read from _cf_chl_opt.
		// Pick the object with the most option-reading fields.
		if optionReads > bestCount && len(fields) > PAYLOAD_FIELDS {
			best = fields
			bestCount = optionReads
		}
		return true
	})

	if best == nil {
		// Fallback: try any object with >PAYLOAD_FIELDS properties.
		walkAST(prog, func(node ast.Node) bool {
			if best != nil {
				return false
			}
			obj, ok := node.(*ast.ObjectLiteral)
			if !ok {
				return true
			}
			if len(obj.Value) <= PAYLOAD_FIELDS {
				return true
			}
			var fields []TemplateField
			for _, prop := range obj.Value {
				if kp, ok := prop.(*ast.PropertyKeyed); ok {
					name := propertyKey(kp.Key)
					if name != "" {
						fields = append(fields, TemplateField{
							Name:       name,
							Expression: kp.Value,
						})
					}
				}
			}
			if len(fields) > PAYLOAD_FIELDS {
				best = fields
			}
			return true
		})
	}

	return best, nil
}

// optionKey extracts the _cf_chl_opt property name from an expression like
// global._cf_chl_opt.NAME or global['_cf_chl_opt'].NAME.
func optionKey(expr ast.Expression) string {
	if expr == nil {
		return ""
	}
	// _cf_chl_opt.NAME (DotExpression)
	if de, ok := expr.(*ast.DotExpression); ok {
		if isCfChlOpt(de.Left) {
			return string(de.Identifier.Name)
		}
	}
	// _cf_chl_opt['NAME'] (BracketExpression)
	if be, ok := expr.(*ast.BracketExpression); ok {
		if isCfChlOpt(be.Left) {
			return staticStr(be.Member)
		}
	}
	// Also handle nested: global._cf_chl_opt.NAME
	if de, ok := expr.(*ast.DotExpression); ok {
		if de2, ok := de.Left.(*ast.DotExpression); ok {
			if isCfChlOpt(de2) || string(de2.Identifier.Name) == "_cf_chl_opt" {
				return string(de.Identifier.Name)
			}
		}
	}
	return ""
}

// optionAssignment extracts the property name from an assignment target like
// _cf_chl_opt.NAME = ...
func optionAssignment(expr ast.Expression) string {
	return optionKey(expr)
}

// isCfChlOpt checks if an expression is or accesses _cf_chl_opt.
func isCfChlOpt(expr ast.Expression) bool {
	if id, ok := expr.(*ast.Identifier); ok {
		return string(id.Name) == "_cf_chl_opt"
	}
	if de, ok := expr.(*ast.DotExpression); ok {
		return string(de.Identifier.Name) == "_cf_chl_opt"
	}
	if be, ok := expr.(*ast.BracketExpression); ok {
		return staticStr(be.Member) == "_cf_chl_opt"
	}
	return false
}

// staticStr extracts a static string from an expression.
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

// propertyKey extracts the key name from a property key.
func propertyKey(expr ast.Expression) string {
	if id, ok := expr.(*ast.Identifier); ok {
		return string(id.Name)
	}
	return staticStr(expr)
}

// contains checks if a slice contains a string.
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// walkAST walks the AST calling fn for each node.
func walkAST(prog *ast.Program, fn func(ast.Node) bool) {
	if prog == nil {
		return
	}
	for _, stmt := range prog.Body {
		walkNode(stmt, fn)
	}
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
		for _, s := range n.Body {
			walkNode(s, fn)
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
		for _, a := range n.ArgumentList {
			walkNode(a, fn)
		}
	case *ast.DotExpression:
		walkNode(n.Left, fn)
	case *ast.BracketExpression:
		walkNode(n.Left, fn)
		walkNode(n.Member, fn)
	case *ast.FunctionLiteral:
		if n.Body != nil {
			for _, s := range n.Body.List {
				walkNode(s, fn)
			}
		}
	case *ast.VariableStatement:
		for _, e := range n.List {
			if e.Initializer != nil {
				walkNode(e.Initializer, fn)
			}
		}
	case *ast.LexicalDeclaration:
		for _, e := range n.List {
			if e.Initializer != nil {
				walkNode(e.Initializer, fn)
			}
		}
	case *ast.ReturnStatement:
		if n.Argument != nil {
			walkNode(n.Argument, fn)
		}
	case *ast.BlockStatement:
		for _, s := range n.List {
			walkNode(s, fn)
		}
	case *ast.IfStatement:
		walkNode(n.Test, fn)
		walkNode(n.Consequent, fn)
		if n.Alternate != nil {
			walkNode(n.Alternate, fn)
		}
	case *ast.UnaryExpression:
		walkNode(n.Operand, fn)
	case *ast.ObjectLiteral:
		for _, p := range n.Value {
			if kp, ok := p.(*ast.PropertyKeyed); ok && kp.Value != nil {
				walkNode(kp.Value, fn)
			}
		}
	case *ast.ArrayLiteral:
		for _, e := range n.Value {
			walkNode(e, fn)
		}
	case *ast.SequenceExpression:
		for _, e := range n.Sequence {
			walkNode(e, fn)
		}
	case *ast.ConditionalExpression:
		walkNode(n.Test, fn)
		walkNode(n.Consequent, fn)
		walkNode(n.Alternate, fn)
	case *ast.TryStatement:
		if n.Body != nil {
			walkNode(n.Body, fn)
		}
	case *ast.WhileStatement:
		walkNode(n.Test, fn)
		walkNode(n.Body, fn)
	case *ast.ForStatement:
		if n.Test != nil {
			walkNode(n.Test, fn)
		}
		walkNode(n.Body, fn)
	case *ast.NewExpression:
		walkNode(n.Callee, fn)
		for _, a := range n.ArgumentList {
			walkNode(a, fn)
		}
	}
}
