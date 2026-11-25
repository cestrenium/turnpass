package vm

import (
	"fmt"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"
)

type Script struct {
	Source  string
	Program *ast.Program
}

func ParseScript(source string) (*Script, error) {
	program, err := parser.ParseFile(nil, "", source, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing script: %w", err)
	}
	return &Script{Source: source, Program: program}, nil
}

type VMDefinition struct {
	Script       *Script
	Class        *ast.ClassLiteral
	Constructor  *ast.FunctionLiteral
	RunFunction  *ast.FunctionLiteral
	DispatchLoop *ast.WhileStatement
	Handlers     map[uint8]*ast.FunctionLiteral
	Functions    map[string]*ast.FunctionLiteral
	Entry        Position
	// classes tracks all class declarations found in the script, used by
	// FindVMByRunner to locate the VM class by name.
	classes []*ast.ClassLiteral
}

func FindVM(script *Script) (*VMDefinition, error) {
	def := &VMDefinition{
		Script:    script,
		Handlers:  make(map[uint8]*ast.FunctionLiteral),
		Functions: make(map[string]*ast.FunctionLiteral),
		Entry:     Position{PC: 0, Key: 0},
	}

	for _, stmt := range script.Program.Body {
		switch s := stmt.(type) {
		case *ast.FunctionDeclaration:
			if s.Function != nil && s.Function.Name != nil {
				def.Functions[string(s.Function.Name.Name)] = s.Function
			}
		case *ast.ClassDeclaration:
			if s.Class != nil {
				if err := def.inspectClass(s.Class); err != nil {
					return nil, err
				}
			}
		case *ast.ExpressionStatement:
			if expr, ok := s.Expression.(*ast.CallExpression); ok {
				if callee, ok := expr.Callee.(*ast.FunctionLiteral); ok && callee.Body != nil {
					for _, bodyStmt := range callee.Body.List {
						switch bs := bodyStmt.(type) {
						case *ast.FunctionDeclaration:
							if bs.Function != nil && bs.Function.Name != nil {
								def.Functions[string(bs.Function.Name.Name)] = bs.Function
							}
						case *ast.ClassDeclaration:
							if bs.Class != nil {
								if err := def.inspectClass(bs.Class); err != nil {
									return nil, err
								}
							}
						}
					}
				}
			}
		}
	}

	if def.Class == nil {
		return nil, fmt.Errorf("no VM class found in script")
	}
	if def.RunFunction == nil {
		return nil, fmt.Errorf("no dispatch loop (run method) found in VM class")
	}

	return def, nil
}

func (def *VMDefinition) inspectClass(class *ast.ClassLiteral) error {
	for _, member := range class.Body {
		m, ok := member.(*ast.MethodDefinition)
		if !ok {
			continue
		}
		if m.Kind == "method" && m.Key != nil {
			name := methodName(m.Key)
			if name == "run" && m.Body != nil {
				def.Class = class
				def.RunFunction = m.Body
				if err := def.extractDispatchLoop(m.Body); err != nil {
					return err
				}
				if err := def.extractConstructor(class); err != nil {
					return err
				}
				if err := def.extractHandlers(); err != nil {
					return err
				}
				return nil
			}
		}
	}
	return nil
}

func (def *VMDefinition) extractDispatchLoop(fn *ast.FunctionLiteral) error {
	if fn.Body == nil {
		return fmt.Errorf("run function has no body")
	}
	// Search for the dispatch loop: a while(true) or for(;;) statement
	// containing a switch. The loop may be nested inside try blocks or
	// if statements.
	var found *ast.WhileStatement
	var foundFor *ast.ForStatement
	findDispatchLoop(fn.Body, &found, &foundFor)
	if found != nil {
		def.DispatchLoop = found
		return nil
	}
	if foundFor != nil {
		// Wrap the for loop body in a synthetic while statement so the
		// rest of the VM code can use DispatchLoop uniformly.
		def.DispatchLoop = &ast.WhileStatement{
			Test: &ast.BooleanLiteral{Value: true},
			Body: foundFor.Body,
		}
		return nil
	}
	return fmt.Errorf("no dispatch loop (while or for) found in run function")
}

// findDispatchLoop recursively searches for a while(true) or for(;;) statement.
func findDispatchLoop(stmt ast.Statement, whileLoop **ast.WhileStatement, forLoop **ast.ForStatement) {
	if *whileLoop != nil || *forLoop != nil {
		return
	}
	switch s := stmt.(type) {
	case *ast.WhileStatement:
		// Check if the test is `true` or `1`.
		if isTrueLiteral(s.Test) {
			*whileLoop = s
			return
		}
		// Even if the test isn't literally true, accept it as the dispatch
		// loop if it contains a switch.
		if hasSwitch(s.Body) {
			*whileLoop = s
			return
		}
	case *ast.ForStatement:
		// for(;;) has no test — this is the dispatch loop pattern
		// used by current Cloudflare builds.
		if s.Test == nil {
			*forLoop = s
			return
		}
		// for(;test;) with a switch is also a dispatch loop.
		if hasSwitch(s.Body) {
			*forLoop = s
			return
		}
	case *ast.BlockStatement:
		for _, bs := range s.List {
			findDispatchLoop(bs, whileLoop, forLoop)
			if *whileLoop != nil || *forLoop != nil {
				return
			}
		}
	case *ast.IfStatement:
		findDispatchLoop(s.Consequent, whileLoop, forLoop)
		if *whileLoop != nil || *forLoop != nil {
			return
		}
		if s.Alternate != nil {
			findDispatchLoop(s.Alternate, whileLoop, forLoop)
		}
	case *ast.TryStatement:
		if s.Body != nil {
			findDispatchLoop(s.Body, whileLoop, forLoop)
		}
	case *ast.LabelledStatement:
		findDispatchLoop(s.Statement, whileLoop, forLoop)
	}
}

// isTrueLiteral checks if an expression is the literal `true` or `1`.
func isTrueLiteral(expr ast.Expression) bool {
	if b, ok := expr.(*ast.BooleanLiteral); ok {
		return b.Value
	}
	if n, ok := expr.(*ast.NumberLiteral); ok {
		if v, ok := n.Value.(float64); ok {
			return v == 1
		}
		if v, ok := n.Value.(int64); ok {
			return v == 1
		}
	}
	return false
}

// hasSwitch checks if a statement contains a switch statement (directly or
// in a block).
func hasSwitch(stmt ast.Statement) bool {
	if stmt == nil {
		return false
	}
	switch s := stmt.(type) {
	case *ast.SwitchStatement:
		return true
	case *ast.BlockStatement:
		for _, bs := range s.List {
			if hasSwitch(bs) {
				return true
			}
		}
	case *ast.IfStatement:
		return hasSwitch(s.Consequent) || (s.Alternate != nil && hasSwitch(s.Alternate))
	case *ast.TryStatement:
		return s.Body != nil && hasSwitch(s.Body)
	}
	return false
}

func (def *VMDefinition) extractConstructor(class *ast.ClassLiteral) error {
	for _, member := range class.Body {
		m, ok := member.(*ast.MethodDefinition)
		if !ok {
			continue
		}
		if m.Body != nil && methodName(m.Key) == "constructor" {
			def.Constructor = m.Body
			return nil
		}
	}
	return fmt.Errorf("no constructor found in VM class")
}

func (def *VMDefinition) extractHandlers() error {
	if def.DispatchLoop == nil {
		return nil
	}

	// First, try to find a switch statement directly in the dispatch loop
	// (the cfsolve pattern: while(true){ switch(opcode^key){...} }).
	var sw *ast.SwitchStatement
	findSwitch(def.DispatchLoop.Body, &sw)

	// If no switch in the dispatch loop, look for a handler dispatch
	// function called from the loop (the current Cloudflare pattern:
	// for(;;){ tgb(opcode_id, ...); } where tgb contains the switch).
	if sw == nil {
		sw = def.findDispatchFunctionSwitch()
	}

	if sw == nil {
		return nil
	}

	for _, c := range sw.Body {
		if c.Test != nil {
			if opcode, ok := extractNumber(c.Test); ok {
				for _, stmt := range c.Consequent {
					if handler := findHandlerCall(stmt); handler != nil {
						def.Handlers[uint8(opcode)] = handler
					}
				}
			}
		}
	}

	return nil
}

// findDispatchFunctionSwitch searches for a handler dispatch function called
// from the dispatch loop. The dispatch function contains a switch statement
// on (firstArg ^ constant) with numeric case labels.
//
// This handles the current Cloudflare VM pattern where the run function's
// loop calls a separate function (e.g. tgb) that contains the handler
// dispatch switch.
func (def *VMDefinition) findDispatchFunctionSwitch() *ast.SwitchStatement {
	if def.DispatchLoop == nil || def.Script == nil {
		return nil
	}

	// Collect all function names called from the dispatch loop body.
	calledFuncs := make(map[string]bool)
	collectCalledFunctions(def.DispatchLoop.Body, calledFuncs)

	// For each called function, check if it contains a switch statement
	// with numeric case labels.
	for name := range calledFuncs {
		if fn, ok := def.Functions[name]; ok && fn.Body != nil {
			var sw *ast.SwitchStatement
			findSwitch(fn.Body, &sw)
			if sw != nil && hasNumericCases(sw) {
				return sw
			}
			// Also try recursing into the function body for nested switches
			// (the dispatch function might call another function that has
			// the switch).
			var nestedSw *ast.SwitchStatement
			findSwitchDeep(fn.Body, &nestedSw)
			if nestedSw != nil && hasNumericCases(nestedSw) {
				return nestedSw
			}
		}
	}

	// If we still haven't found a switch, try all collected functions
	// and look for ones with large switches (many numeric cases).
	for name, fn := range def.Functions {
		if fn == nil || fn.Body == nil {
			continue
		}
		var sw *ast.SwitchStatement
		findSwitch(fn.Body, &sw)
		if sw != nil && countNumericCases(sw) > 5 {
			// This is likely the dispatch function.
			_ = name
			return sw
		}
	}
	return nil
}

// findSwitchDeep recursively searches for a switch statement in all nested
// statements.
func findSwitchDeep(stmt ast.Statement, sw **ast.SwitchStatement) {
	if *sw != nil || stmt == nil {
		return
	}
	if s, ok := stmt.(*ast.SwitchStatement); ok {
		*sw = s
		return
	}
	switch s := stmt.(type) {
	case *ast.BlockStatement:
		for _, bs := range s.List {
			findSwitchDeep(bs, sw)
			if *sw != nil {
				return
			}
		}
	case *ast.IfStatement:
		findSwitchDeep(s.Consequent, sw)
		if *sw != nil {
			return
		}
		if s.Alternate != nil {
			findSwitchDeep(s.Alternate, sw)
		}
	case *ast.WhileStatement:
		findSwitchDeep(s.Body, sw)
	case *ast.ForStatement:
		findSwitchDeep(s.Body, sw)
	case *ast.TryStatement:
		if s.Body != nil {
			findSwitchDeep(s.Body, sw)
		}
		if s.Catch != nil {
			findSwitchDeep(s.Catch, sw)
		}
	case *ast.SwitchStatement:
		// Already handled above, but also search case bodies.
		for _, c := range s.Body {
			for _, cs := range c.Consequent {
				findSwitchDeep(cs, sw)
				if *sw != nil {
					return
				}
			}
		}
	case *ast.LabelledStatement:
		findSwitchDeep(s.Statement, sw)
	}
}

// countNumericCases counts the number of cases with numeric test values.
func countNumericCases(sw *ast.SwitchStatement) int {
	count := 0
	for _, c := range sw.Body {
		if c.Test != nil {
			if _, ok := extractNumber(c.Test); ok {
				count++
			}
		}
	}
	return count
}

// collectCalledFunctions walks a statement and collects all global function
// names that are called.
func collectCalledFunctions(stmt ast.Statement, called map[string]bool) {
	if stmt == nil {
		return
	}
	switch s := stmt.(type) {
	case *ast.ExpressionStatement:
		collectCalledFunctionsFromExpr(s.Expression, called)
	case *ast.BlockStatement:
		for _, bs := range s.List {
			collectCalledFunctions(bs, called)
		}
	case *ast.IfStatement:
		collectCalledFunctionsFromExpr(s.Test, called)
		collectCalledFunctions(s.Consequent, called)
		if s.Alternate != nil {
			collectCalledFunctions(s.Alternate, called)
		}
	case *ast.ForStatement:
		if n, ok := s.Initializer.(*ast.ForLoopInitializerExpression); ok {
			collectCalledFunctionsFromExpr(n.Expression, called)
		}
		if s.Test != nil {
			collectCalledFunctionsFromExpr(s.Test, called)
		}
		if s.Update != nil {
			collectCalledFunctionsFromExpr(s.Update, called)
		}
		collectCalledFunctions(s.Body, called)
	case *ast.WhileStatement:
		collectCalledFunctionsFromExpr(s.Test, called)
		collectCalledFunctions(s.Body, called)
	case *ast.TryStatement:
		if s.Body != nil {
			collectCalledFunctions(s.Body, called)
		}
		if s.Catch != nil {
			collectCalledFunctions(s.Catch, called)
		}
	case *ast.ReturnStatement:
		if s.Argument != nil {
			collectCalledFunctionsFromExpr(s.Argument, called)
		}
	}
}

// collectCalledFunctionsFromExpr walks an expression and collects all global
// function names that are called.
func collectCalledFunctionsFromExpr(expr ast.Expression, called map[string]bool) {
	if expr == nil {
		return
	}
	switch e := expr.(type) {
	case *ast.CallExpression:
		if id, ok := e.Callee.(*ast.Identifier); ok {
			called[string(id.Name)] = true
		}
		// Recurse into callee and arguments.
		collectCalledFunctionsFromExpr(e.Callee, called)
		for _, arg := range e.ArgumentList {
			collectCalledFunctionsFromExpr(arg, called)
		}
	case *ast.BinaryExpression:
		collectCalledFunctionsFromExpr(e.Left, called)
		collectCalledFunctionsFromExpr(e.Right, called)
	case *ast.UnaryExpression:
		collectCalledFunctionsFromExpr(e.Operand, called)
	case *ast.ConditionalExpression:
		collectCalledFunctionsFromExpr(e.Test, called)
		collectCalledFunctionsFromExpr(e.Consequent, called)
		collectCalledFunctionsFromExpr(e.Alternate, called)
	case *ast.SequenceExpression:
		for _, se := range e.Sequence {
			collectCalledFunctionsFromExpr(se, called)
		}
	case *ast.AssignExpression:
		collectCalledFunctionsFromExpr(e.Left, called)
		collectCalledFunctionsFromExpr(e.Right, called)
	case *ast.DotExpression:
		collectCalledFunctionsFromExpr(e.Left, called)
	case *ast.BracketExpression:
		collectCalledFunctionsFromExpr(e.Left, called)
		collectCalledFunctionsFromExpr(e.Member, called)
	}
}

// hasNumericCases checks if a switch statement has at least one case with a
// numeric test value.
func hasNumericCases(sw *ast.SwitchStatement) bool {
	for _, c := range sw.Body {
		if c.Test != nil {
			if _, ok := extractNumber(c.Test); ok {
				return true
			}
		}
	}
	return false
}

func methodName(key ast.Expression) string {
	if id, ok := key.(*ast.Identifier); ok {
		return string(id.Name)
	}
	if lit, ok := key.(*ast.StringLiteral); ok {
		return string(lit.Value)
	}
	return ""
}

func extractNumber(expr ast.Expression) (float64, bool) {
	switch e := expr.(type) {
	case *ast.NumberLiteral:
		if n, ok := e.Value.(float64); ok {
			return n, true
		}
	case *ast.UnaryExpression:
		if e.Operator == token.MINUS {
			if n, ok := extractNumber(e.Operand); ok {
				return -n, true
			}
		}
	}
	return 0, false
}

func findSwitch(stmt ast.Statement, sw **ast.SwitchStatement) {
	if *sw != nil {
		return
	}
	if s, ok := stmt.(*ast.SwitchStatement); ok {
		*sw = s
		return
	}
	if block, ok := stmt.(*ast.BlockStatement); ok {
		for _, s := range block.List {
			findSwitch(s, sw)
			if *sw != nil {
				return
			}
		}
	}
}

func findHandlerCall(stmt ast.Statement) *ast.FunctionLiteral {
	switch s := stmt.(type) {
	case *ast.ExpressionStatement:
		return findHandlerInExpression(s.Expression)
	case *ast.BlockStatement:
		for _, bs := range s.List {
			if h := findHandlerCall(bs); h != nil {
				return h
			}
		}
	}
	return nil
}

func findHandlerInExpression(expr ast.Expression) *ast.FunctionLiteral {
	switch e := expr.(type) {
	case *ast.FunctionLiteral:
		return e
	case *ast.AssignExpression:
		if fn := findHandlerInExpression(e.Right); fn != nil {
			return fn
		}
	case *ast.CallExpression:
		for _, arg := range e.ArgumentList {
			if fn := findHandlerInExpression(arg); fn != nil {
				return fn
			}
		}
	}
	return nil
}

func (def *VMDefinition) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("VM{handlers: %d, functions: %d", len(def.Handlers), len(def.Functions)))
	if def.Class != nil {
		sb.WriteString(", class: found")
	}
	if def.RunFunction != nil {
		sb.WriteString(", run: found")
	}
	if def.DispatchLoop != nil {
		sb.WriteString(", dispatch: found")
	}
	sb.WriteString("}")
	return sb.String()
}

// RunnerInfo holds the names and initial values extracted from the program
// runner installation pattern:
//
//	<global>.<name> = function(p){ return <run>(new <Class>(p), pc, key, []); }
type RunnerInfo struct {
	Name       string  // the property name on the global object
	RunFunc    string  // the run function name
	VMClass    string  // the VM class name
	InitialPC  float64 // initial program counter
	InitialKey float64 // initial dispatch key
}

// FindVMByRunner finds the VM class and run function by name, using runner
// info extracted from the program runner installation pattern. This handles
// the orchestrator's VM layout where the run function is standalone (not a
// method on the class) and the class only has a constructor.
func FindVMByRunner(script *Script, runner RunnerInfo) (*VMDefinition, error) {
	def := &VMDefinition{
		Script:    script,
		Handlers:  make(map[uint8]*ast.FunctionLiteral),
		Functions: make(map[string]*ast.FunctionLiteral),
		Entry:     Position{PC: uint32(runner.InitialPC), Key: uint8(int(runner.InitialKey) & 0xFF)},
	}

	// Walk the AST to collect all function declarations, class declarations,
	// and functions assigned to variables.
	walkProgramForDecls(script.Program, def)

	// Find the VM class by name.
	if runner.VMClass != "" {
		if class, ok := def.findClassByName(runner.VMClass); ok {
			def.Class = class
			if err := def.extractConstructor(class); err != nil {
				return nil, fmt.Errorf("extracting constructor from %s: %w", runner.VMClass, err)
			}
		}
	}

	// Find the run function by name.
	if runner.RunFunc != "" {
		if fn, ok := def.Functions[runner.RunFunc]; ok {
			def.RunFunction = fn
			if err := def.extractDispatchLoop(fn); err != nil {
				return nil, fmt.Errorf("extracting dispatch loop from %s: %w", runner.RunFunc, err)
			}
			if err := def.extractHandlers(); err != nil {
				return nil, fmt.Errorf("extracting handlers: %w", err)
			}
		}
	}

	if def.Class == nil {
		return nil, fmt.Errorf("no VM class found (looking for %q)", runner.VMClass)
	}
	if def.RunFunction == nil {
		return nil, fmt.Errorf("no run function found (looking for %q)", runner.RunFunc)
	}

	return def, nil
}

// walkProgramForDecls walks the program and collects all function and class
// declarations into the VMDefinition's Functions map and tracks classes.
func walkProgramForDecls(prog *ast.Program, def *VMDefinition) {
	walkNodeForDecls(prog, def)
}

// walkNodeForDecls recursively walks any AST node and collects declarations.
func walkNodeForDecls(node ast.Node, def *VMDefinition) {
	if node == nil {
		return
	}
	switch n := node.(type) {
	case *ast.Program:
		for _, stmt := range n.Body {
			walkNodeForDecls(stmt, def)
		}
	case *ast.FunctionLiteral:
		// Track named function literals.
		if n.Name != nil && n.Name.Name != "" {
			def.Functions[string(n.Name.Name)] = n
		}
		// Walk the body for nested declarations.
		if n.Body != nil {
			for _, stmt := range n.Body.List {
				walkNodeForDecls(stmt, def)
			}
		}
	case *ast.FunctionDeclaration:
		if n.Function != nil {
			walkNodeForDecls(n.Function, def)
		}
	case *ast.ClassDeclaration:
		if n.Class != nil {
			def.classes = append(def.classes, n.Class)
			// Walk the class body for nested declarations.
			for _, member := range n.Class.Body {
				if m, ok := member.(*ast.MethodDefinition); ok && m.Body != nil {
					walkNodeForDecls(m.Body, def)
				}
			}
		}
	case *ast.ClassLiteral:
		for _, member := range n.Body {
			if m, ok := member.(*ast.MethodDefinition); ok && m.Body != nil {
				walkNodeForDecls(m.Body, def)
			}
		}
	case *ast.ExpressionStatement:
		walkNodeForDecls(n.Expression, def)
	case *ast.BlockStatement:
		for _, stmt := range n.List {
			walkNodeForDecls(stmt, def)
		}
	case *ast.VariableStatement:
		for _, binding := range n.List {
			if id, ok := binding.Target.(*ast.Identifier); ok && binding.Initializer != nil {
				if fn, ok := binding.Initializer.(*ast.FunctionLiteral); ok {
					def.Functions[string(id.Name)] = fn
				}
				walkNodeForDecls(binding.Initializer, def)
			}
		}
	case *ast.LexicalDeclaration:
		for _, binding := range n.List {
			if id, ok := binding.Target.(*ast.Identifier); ok && binding.Initializer != nil {
				if fn, ok := binding.Initializer.(*ast.FunctionLiteral); ok {
					def.Functions[string(id.Name)] = fn
				}
				walkNodeForDecls(binding.Initializer, def)
			}
		}
	case *ast.IfStatement:
		walkNodeForDecls(n.Test, def)
		walkNodeForDecls(n.Consequent, def)
		if n.Alternate != nil {
			walkNodeForDecls(n.Alternate, def)
		}
	case *ast.WhileStatement:
		walkNodeForDecls(n.Test, def)
		walkNodeForDecls(n.Body, def)
	case *ast.DoWhileStatement:
		walkNodeForDecls(n.Body, def)
		walkNodeForDecls(n.Test, def)
	case *ast.ForStatement:
		if n.Initializer != nil {
			walkNodeForDecls(n.Initializer, def)
		}
		if n.Test != nil {
			walkNodeForDecls(n.Test, def)
		}
		if n.Update != nil {
			walkNodeForDecls(n.Update, def)
		}
		walkNodeForDecls(n.Body, def)
	case *ast.ForInStatement:
		walkNodeForDecls(n.Source, def)
		walkNodeForDecls(n.Body, def)
	case *ast.ForOfStatement:
		walkNodeForDecls(n.Source, def)
		walkNodeForDecls(n.Body, def)
	case *ast.TryStatement:
		if n.Body != nil {
			walkNodeForDecls(n.Body, def)
		}
		if n.Catch != nil {
			walkNodeForDecls(n.Catch, def)
		}
		if n.Finally != nil {
			walkNodeForDecls(n.Finally, def)
		}
	case *ast.SwitchStatement:
		walkNodeForDecls(n.Discriminant, def)
		for _, c := range n.Body {
			walkNodeForDecls(c, def)
		}
	case *ast.CaseStatement:
		if n.Test != nil {
			walkNodeForDecls(n.Test, def)
		}
		for _, s := range n.Consequent {
			walkNodeForDecls(s, def)
		}
	case *ast.ReturnStatement:
		if n.Argument != nil {
			walkNodeForDecls(n.Argument, def)
		}
	case *ast.AssignExpression:
		// var = function(){...} — track the function.
		if id, ok := n.Left.(*ast.Identifier); ok {
			if fn, ok := n.Right.(*ast.FunctionLiteral); ok {
				def.Functions[string(id.Name)] = fn
			}
		}
		walkNodeForDecls(n.Left, def)
		walkNodeForDecls(n.Right, def)
	case *ast.CallExpression:
		walkNodeForDecls(n.Callee, def)
		for _, arg := range n.ArgumentList {
			walkNodeForDecls(arg, def)
		}
	case *ast.NewExpression:
		walkNodeForDecls(n.Callee, def)
		for _, arg := range n.ArgumentList {
			walkNodeForDecls(arg, def)
		}
	case *ast.BinaryExpression:
		walkNodeForDecls(n.Left, def)
		walkNodeForDecls(n.Right, def)
	case *ast.SequenceExpression:
		for _, e := range n.Sequence {
			walkNodeForDecls(e, def)
		}
	case *ast.ConditionalExpression:
		walkNodeForDecls(n.Test, def)
		walkNodeForDecls(n.Consequent, def)
		walkNodeForDecls(n.Alternate, def)
	case *ast.UnaryExpression:
		walkNodeForDecls(n.Operand, def)
	case *ast.DotExpression:
		walkNodeForDecls(n.Left, def)
	case *ast.BracketExpression:
		walkNodeForDecls(n.Left, def)
		walkNodeForDecls(n.Member, def)
	case *ast.ThrowStatement:
		if n.Argument != nil {
			walkNodeForDecls(n.Argument, def)
		}
	case *ast.LabelledStatement:
		walkNodeForDecls(n.Statement, def)
	}
}

// collectDecls is kept for backward compatibility but delegates to
// walkNodeForDecls.
func collectDecls(stmt ast.Statement, def *VMDefinition) {
	walkNodeForDecls(stmt, def)
}

// collectDeclsFromExpr is kept for backward compatibility but delegates to
// walkNodeForDecls.
func collectDeclsFromExpr(expr ast.Expression, def *VMDefinition) {
	walkNodeForDecls(expr, def)
}

// classNameOf is reserved for future use; goja stores class names on the
// ClassDeclaration, not the ClassLiteral.
func classNameOf(class *ast.ClassLiteral) string {
	return ""
}

// findClassByName searches all collected classes. Since the orchestrator
// typically has exactly one VM class, we return the first one found.
// The name parameter is used for error messages only.
func (def *VMDefinition) findClassByName(name string) (*ast.ClassLiteral, bool) {
	if len(def.classes) > 0 {
		return def.classes[0], true
	}
	return nil, false
}
