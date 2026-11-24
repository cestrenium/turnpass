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
	for _, stmt := range fn.Body.List {
		if while, ok := stmt.(*ast.WhileStatement); ok {
			def.DispatchLoop = while
			return nil
		}
	}
	return fmt.Errorf("no while loop found in run function")
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

	var sw *ast.SwitchStatement
	findSwitch(def.DispatchLoop.Body, &sw)
	if sw == nil {
		return fmt.Errorf("no switch statement found in dispatch loop")
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
