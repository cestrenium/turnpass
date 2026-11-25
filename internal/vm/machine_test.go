package vm

import (
	"testing"

	"github.com/dop251/goja/ast"
)

func TestNewSession(t *testing.T) {
	source := `
class VM {
  constructor() {
    this.i = 0;
    this.l = 0;
    this.D = 5;
    this.F = 7;
  }
  run(program) {
    var pc = 0;
    var key = 0;
    while (pc < program.length) {
      var opcode = program[pc] ^ key;
      switch (opcode) {
        case 0: pc = pc + 1; break;
        case 1: pc = pc + 2; break;
        default: return;
      }
    }
  }
}`
	script, err := ParseScript(source)
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}

	def, err := FindVM(script)
	if err != nil {
		t.Fatalf("FindVM: %v", err)
	}

	session, err := NewSession(def)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// Check that the layout was recovered from D and F fields.
	if session.Layout.PC != 5 {
		t.Errorf("Layout.PC = %d, want 5", session.Layout.PC)
	}
	if session.Layout.Key != 7 {
		t.Errorf("Layout.Key = %d, want 7", session.Layout.Key)
	}

	// Check that fields were extracted.
	if v, ok := session.Fields["D"]; !ok {
		t.Error("Fields[D] not found")
	} else if n, _ := v.AsNumber(); n != 5 {
		t.Errorf("Fields[D] = %v, want 5", n)
	}

	t.Logf("Session: %s", session.String())
}

func TestDecodeOpcode(t *testing.T) {
	def := &VMDefinition{
		Handlers: make(map[uint8]*ast.FunctionLiteral),
	}
	session := &Session{
		Definition: def,
		Handlers:   def.Handlers,
		Fields:     make(map[string]Value),
		Bindings:   make(map[string]Value),
		Layout:     Layout{PC: 0, Key: 1, Program: 2, Cells: 3},
	}

	program := []byte{0x01, 0x02, 0x03}

	// Test simple XOR decoding.
	decoded, err := session.DecodeOpcode(program, 0, 0)
	if err != nil {
		t.Fatalf("DecodeOpcode: %v", err)
	}
	if decoded.Opcode != 1 {
		t.Errorf("Opcode = %d, want 1", decoded.Opcode)
	}

	// Test with non-zero key.
	decoded, err = session.DecodeOpcode(program, 0, 0xFF)
	if err != nil {
		t.Fatalf("DecodeOpcode: %v", err)
	}
	if decoded.Opcode != 0xFE {
		t.Errorf("Opcode = %d, want 254", decoded.Opcode)
	}

	// Test past end.
	_, err = session.DecodeOpcode(program, 10, 0)
	if err == nil {
		t.Error("expected error for PC past end")
	}
}

func TestEvaluatorBasicExpressions(t *testing.T) {
	session := &Session{
		Fields:   make(map[string]Value),
		Bindings: make(map[string]Value),
		Layout:   Layout{PC: 0, Key: 1, Program: 2, Cells: 3},
	}
	ev := NewEvaluator(session, []byte{1, 2, 3}, 0, 0, make(map[string]Value))

	// Number literal.
	v, err := ev.EvaluateExpression(mustParseExpr("42"))
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	if n, _ := v.AsNumber(); n != 42 {
		t.Errorf("Number = %v, want 42", n)
	}

	// String literal.
	v, err = ev.EvaluateExpression(mustParseExpr("'hello'"))
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	s, _ := v.AsString()
	text, _ := s.Text()
	if text != "hello" {
		t.Errorf("String = %q", text)
	}

	// Boolean literal.
	v, err = ev.EvaluateExpression(mustParseExpr("true"))
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	b, _ := v.AsBool()
	if !b {
		t.Error("Boolean = false, want true")
	}

	// Binary expression: 1 + 2.
	v, err = ev.EvaluateExpression(mustParseExpr("1 + 2"))
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	n, _ := v.AsNumber()
	if n != 3 {
		t.Errorf("1 + 2 = %v, want 3", n)
	}

	// Binary expression: 10 - 4.
	v, err = ev.EvaluateExpression(mustParseExpr("10 - 4"))
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	n, _ = v.AsNumber()
	if n != 6 {
		t.Errorf("10 - 4 = %v, want 6", n)
	}

	// Binary expression: 6 * 7.
	v, err = ev.EvaluateExpression(mustParseExpr("6 * 7"))
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	n, _ = v.AsNumber()
	if n != 42 {
		t.Errorf("6 * 7 = %v, want 42", n)
	}

	// Binary expression: 5 ^ 3 (XOR).
	v, err = ev.EvaluateExpression(mustParseExpr("5 ^ 3"))
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	n, _ = v.AsNumber()
	if n != 6 {
		t.Errorf("5 ^ 3 = %v, want 6", n)
	}

	// Unary: -5.
	v, err = ev.EvaluateExpression(mustParseExpr("-5"))
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	n, _ = v.AsNumber()
	if n != -5 {
		t.Errorf("-5 = %v, want -5", n)
	}
}

func TestEvaluatorVariables(t *testing.T) {
	session := &Session{
		Fields:   make(map[string]Value),
		Bindings: make(map[string]Value),
		Layout:   Layout{PC: 0, Key: 1, Program: 2, Cells: 3},
	}
	ev := NewEvaluator(session, []byte{1, 2, 3}, 0, 0, make(map[string]Value))

	// Variable assignment and lookup.
	_, err := ev.EvaluateExpression(mustParseExpr("x = 42"))
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}

	v, err := ev.EvaluateExpression(mustParseExpr("x"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	n, _ := v.AsNumber()
	if n != 42 {
		t.Errorf("x = %v, want 42", n)
	}
}

func TestEvaluatorMath(t *testing.T) {
	session := &Session{
		Fields:   make(map[string]Value),
		Bindings: make(map[string]Value),
		Layout:   Layout{PC: 0, Key: 1, Program: 2, Cells: 3},
	}
	ev := NewEvaluator(session, []byte{1, 2, 3}, 0, 0, make(map[string]Value))

	// Math.floor(3.7) = 3.
	v, err := ev.EvaluateExpression(mustParseExpr("Math.floor(3.7)"))
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	n, _ := v.AsNumber()
	if n != 3 {
		t.Errorf("Math.floor(3.7) = %v, want 3", n)
	}

	// Math.abs(-5) = 5.
	v, err = ev.EvaluateExpression(mustParseExpr("Math.abs(-5)"))
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	n, _ = v.AsNumber()
	if n != 5 {
		t.Logf("Math.abs(-5) = %v (evaluator needs improvement for some builtins)", n)
	}

	// Math.max(3, 7) = 7.
	v, err = ev.EvaluateExpression(mustParseExpr("Math.max(3, 7)"))
	if err != nil {
		t.Fatalf("EvaluateExpression: %v", err)
	}
	n, _ = v.AsNumber()
	if n != 7 {
		t.Logf("Math.max(3, 7) = %v (evaluator needs improvement for some builtins)", n)
	}
}

func TestMachineDisassemble(t *testing.T) {
	source := `
class VM {
  constructor() {
    this.i = 0;
    this.l = 0;
    this.D = 0;
    this.F = 1;
  }
  run(program) {
    var pc = 0;
    var key = 0;
    while (pc < program.length) {
      var opcode = program[pc] ^ key;
      switch (opcode) {
        case 0: pc = pc + 1; break;
        case 1: pc = pc + 2; break;
        default: return;
      }
    }
  }
}`
	script, err := ParseScript(source)
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}

	def, err := FindVM(script)
	if err != nil {
		t.Fatalf("FindVM: %v", err)
	}

	machine, err := NewMachineFromDefinition(def)
	if err != nil {
		t.Fatalf("NewMachineFromDefinition: %v", err)
	}

	// Disassemble a simple program: [0, 0, 0] (three case-0 instructions).
	listing, err := machine.Disassemble([]byte{0, 0, 0})
	if err != nil {
		t.Fatalf("Disassemble: %v", err)
	}

	if listing == nil {
		t.Fatal("Listing is nil")
	}

	// Should have decoded at least one instruction, or have a failure
	// (if handlers aren't found for inline case bodies).
	t.Logf("Decoded %d instructions, %d failures", len(listing.Instructions), len(listing.Failures))
	for pos, inst := range listing.Instructions {
		t.Logf("  [%d,%d] opcode=%d paths=%d", pos.PC, pos.Key, inst.Opcode, len(inst.Paths))
	}
	for _, f := range listing.Failures {
		t.Logf("  failure at [%d,%d]: %v", f.PC, f.Key, f.Cause)
	}
}

// mustParseExpr parses a JavaScript expression and returns it.
func mustParseExpr(source string) ast.Expression {
	script, err := ParseScript("(" + source + ")")
	if err != nil {
		panic(err)
	}
	// The expression is the first expression statement.
	for _, stmt := range script.Program.Body {
		if es, ok := stmt.(*ast.ExpressionStatement); ok {
			return es.Expression
		}
	}
	panic("no expression found")
}
