package vm

import (
	"fmt"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/token"
)

// Session holds the VM state initialized from the script before any program runs.
type Session struct {
	Definition *VMDefinition
	Layout     Layout
	Handlers   map[uint8]*ast.FunctionLiteral
	Fields     map[string]Value
	Bindings   map[string]Value
	Initial    []RegisterInit
	Entry      Position
}

type RegisterInit struct {
	Register uint8
	Value    Value
}

func NewSession(def *VMDefinition) (*Session, error) {
	s := &Session{
		Definition: def,
		Handlers:   def.Handlers,
		Fields:     make(map[string]Value),
		Bindings:   make(map[string]Value),
		Entry:      def.Entry,
	}
	if def.Constructor != nil && def.Constructor.Body != nil {
		s.evaluateConstructor(def.Constructor)
	}
	s.recoverLayout()
	return s, nil
}

func (s *Session) evaluateConstructor(fn *ast.FunctionLiteral) {
	if fn.Body == nil {
		return
	}
	for _, stmt := range fn.Body.List {
		s.evaluateConstructorStatement(stmt)
	}
}

func (s *Session) evaluateConstructorStatement(stmt ast.Statement) {
	switch st := stmt.(type) {
	case *ast.ExpressionStatement:
		s.evaluateConstructorExpression(st.Expression)
	case *ast.BlockStatement:
		for _, bs := range st.List {
			s.evaluateConstructorStatement(bs)
		}
	}
}

func (s *Session) evaluateConstructorExpression(expr ast.Expression) {
	if e, ok := expr.(*ast.AssignExpression); ok {
		if e.Operator == token.ASSIGN {
			if member, ok := e.Left.(*ast.DotExpression); ok {
				if _, isThis := member.Left.(*ast.ThisExpression); isThis {
					fieldName := string(member.Identifier.Name)
					if val, ok := extractValue(e.Right); ok {
						s.Fields[fieldName] = val
					}
				}
			}
		}
	}
}

func (s *Session) recoverLayout() {
	if pcIdx, ok := s.Fields["D"]; ok {
		if n, ok := pcIdx.AsNumber(); ok {
			s.Layout.PC = uint8(n)
		}
	}
	if keyIdx, ok := s.Fields["F"]; ok {
		if n, ok := keyIdx.AsNumber(); ok {
			s.Layout.Key = uint8(n)
		}
	}
	if s.Layout.PC == 0 && s.Layout.Key == 0 {
		s.Layout = Layout{PC: 0, Key: 1, Program: 2, Cells: 3}
	}
}

func (s *Session) ConstructedFields(program []byte) map[string]Value {
	fields := make(map[string]Value)
	for k, v := range s.Fields {
		fields[k] = v
	}
	return fields
}

func extractValue(expr ast.Expression) (Value, bool) {
	switch e := expr.(type) {
	case *ast.NumberLiteral:
		return NumberVal(toFloat64(e.Value)), true
	case *ast.StringLiteral:
		return StringVal(string(e.Value)), true
	case *ast.BooleanLiteral:
		return BoolVal(e.Value), true
	case *ast.NullLiteral:
		return Null(), true
	case *ast.UnaryExpression:
		if e.Operator == token.MINUS {
			if v, ok := extractValue(e.Operand); ok {
				if n, ok := v.AsNumber(); ok {
					return NumberVal(-n), true
				}
			}
		}
	}
	return Value{}, false
}

func (s *Session) String() string {
	return fmt.Sprintf("Session{layout: %+v, handlers: %d, fields: %d}", s.Layout, len(s.Handlers), len(s.Fields))
}

// Decoded holds the result of decoding one program byte.
type Decoded struct {
	Opcode uint8
	Key    uint8
}

// DecodeOpcode decodes the opcode at the given program counter using the dispatch key.
func (s *Session) DecodeOpcode(program []byte, pc uint32, key uint8) (Decoded, error) {
	if int(pc) >= len(program) {
		return Decoded{}, fmt.Errorf("program counter %d past end (length %d)", pc, len(program))
	}
	opcode := program[pc] ^ key
	nextKey := opcode
	return Decoded{Opcode: opcode, Key: nextKey}, nil
}
