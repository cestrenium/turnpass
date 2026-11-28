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
	"github.com/dop251/goja/token"

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
// cfChlOptValues are the standard-name values from the challenge page HTML
// (cH, cFPWv, cRay, cUPMDTk, cITimeS).
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

	// Build the options map by tracking renames.
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
// orchestrator renames. The orchestrator copies standard names (cH, cFPWv,
// etc.) to obfuscated _hex names and deletes the originals.
func buildOptions(prog *ast.Program, cfChlOptValues map[string]string) expression.Options {
	options := make(expression.Options)

	// Start with standard-name values from the HTML.
	for k, v := range cfChlOptValues {
		options[k] = js.String(v)
	}

	// Track renames: _cf_chl_opt._newname = _cf_chl_opt._oldname
	// combined with: delete _cf_chl_opt._oldname
	type rename struct {
		to, from string
	}
	var renames []rename
	var deleted []string

	walkAST(prog, func(node ast.Node) bool {
		// Assignment: _cf_chl_opt.X = _cf_chl_opt.Y
		if ae, ok := node.(*ast.AssignExpression); ok {
			to := optionAssignment(ae.Left)
			if to != "" {
				from := optionKey(ae.Right)
				if from != "" {
					renames = append(renames, rename{to, from})
				}
			}
		}
		// Delete: delete _cf_chl_opt.X
		if ue, ok := node.(*ast.UnaryExpression); ok && ue.Operator == token.DELETE {
			opt := optionKey(ue.Operand)
			if opt != "" {
				deleted = append(deleted, opt)
			}
		}
		return true
	})

	// Apply renames: move values from old names to new names.
	deletedSet := make(map[string]bool)
	for _, d := range deleted {
		deletedSet[d] = true
	}
	for _, r := range renames {
		if deletedSet[r.from] {
			if val, ok := options[r.from]; ok {
				if _, exists := options[r.to]; !exists {
					options[r.to] = val
					delete(options, r.from)
				}
			}
		}
	}

	return options
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
