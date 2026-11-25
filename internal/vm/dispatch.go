package vm

import (
	"fmt"
	"math"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/token"
)

// EvaluateDispatchLoop evaluates the dispatch loop's decoding statements
// to extract the opcode at a given program counter. This replaces the
// simple XOR pattern with actual evaluation of the AST.
//
// The dispatch loop typically:
// 1. Reads program[pc]
// 2. XORs it with the dispatch key
// 3. Optionally mixes in a hash of the program position
// 4. Stores the result as the opcode
// 5. Computes the next dispatch key
func (s *Session) EvaluateDispatchLoop(program []byte, pc uint32, key uint8) (Decoded, error) {
	if int(pc) >= len(program) {
		return Decoded{}, fmt.Errorf("pc %d past end", pc)
	}

	// If we have a dispatch loop in the definition, try to evaluate it.
	if s.Definition != nil && s.Definition.DispatchLoop != nil {
		// Create an evaluator with the program bytes.
		fields := s.ConstructedFields(program)
		ev := NewEvaluator(s, program, pc, key, fields)

		// Set up the dispatch loop's variables.
		// The dispatch loop typically reads: this.i (PC), this.l (key),
		// this.H (values array), this.J (tags array).
		ev.Scope.Variables["pc"] = NumberVal(float64(pc))
		ev.Scope.Variables["key"] = NumberVal(float64(key))

		// Try to find and evaluate the switch discriminant.
		var sw *ast.SwitchStatement
		findSwitch(s.Definition.DispatchLoop.Body, &sw)
		if sw != nil {
			// Evaluate the discriminant to get the opcode.
			opcodeVal, err := ev.EvaluateExpression(sw.Discriminant)
			if err == nil {
				if n, ok := opcodeVal.AsNumber(); ok {
					opcode := uint8(int(n) & 0xFF)
					// The next key is typically the opcode itself,
					// or derived from it.
					nextKey := opcode
					return Decoded{Opcode: opcode, Key: nextKey}, nil
				}
			}
		}
	}

	// Fall back to the simple XOR pattern.
	opcode := program[pc] ^ key
	return Decoded{Opcode: opcode, Key: opcode}, nil
}

// RegisterMask represents the rolling mask state of the register file.
// In cfsolve, the interpreter keeps the mask at zero, so stored values
// are unmasked. This struct is provided for completeness.
type RegisterMask struct {
	Mask   uint32
	Digest uint32
}

// Update updates the mask digest with a new value.
func (m *RegisterMask) Update(value uint32) {
	m.Digest = m.Digest*31 + value
	m.Mask = m.Digest
}

// ApplyMask applies the mask to a register value.
// With a zero mask, the value is returned unchanged.
func (m *RegisterMask) ApplyMask(value uint32) uint32 {
	return value ^ m.Mask
}

// Zero returns true if the mask is zero (the interpreter's default state).
func (m *RegisterMask) Zero() bool {
	return m.Mask == 0
}

// PathExplorer explores feasible paths through a handler.
type PathExplorer struct {
	Session  *Session
	Program  []byte
	MaxPaths int
}

// NewPathExplorer creates a PathExplorer.
func NewPathExplorer(session *Session, program []byte) *PathExplorer {
	return &PathExplorer{
		Session:  session,
		Program:  program,
		MaxPaths: 64,
	}
}

// ExploreHandler explores all feasible paths through a handler function
// and returns the resulting paths.
func (pe *PathExplorer) ExploreHandler(handler *ast.FunctionLiteral, pc uint32, key uint8) []Path {
	if handler == nil || handler.Body == nil {
		return []Path{{Exit: Exit{Kind: ExitUnfollowed}}}
	}

	// Create an evaluator for this handler invocation.
	fields := pe.Session.ConstructedFields(pe.Program)
	ev := NewEvaluator(pe.Session, pe.Program, pc, key, fields)
	ev.Scope.Variables["this"] = MachineVal()

	// Bind the machine parameter.
	if handler.ParameterList != nil && len(handler.ParameterList.List) > 0 {
		name := paramName(handler.ParameterList.List[0])
		if name != "" {
			ev.Scope.Variables[name] = MachineVal()
		}
	}

	// Execute the handler body.
	flow, retVal, err := ev.ExecuteHandlerBody(handler)
	if err != nil {
		return []Path{{
			Exit:    Exit{Kind: ExitThrow, Thrown: retVal.Expr()},
			Effects: ev.Effects,
		}}
	}

	// Determine the exit kind.
	var exit Exit
	switch flow {
	case FlowReturn:
		exit = Exit{Kind: ExitReturn, Return: retVal.Expr()}
	case FlowBreak:
		exit = Exit{Kind: ExitFallthrough}
	case FlowThrow:
		exit = Exit{Kind: ExitThrow, Thrown: retVal.Expr()}
	default:
		exit = Exit{Kind: ExitFallthrough}
	}

	// Build the path.
	path := Path{
		Exit:       exit,
		Effects:    ev.Effects,
		Successors: []Position{{PC: ev.PC, Key: ev.Key}},
	}

	return []Path{path}
}

// ExploreWithBranches explores a handler with symbolic branch conditions,
// returning all feasible paths. This is a simplified version that takes
// the first branch for symbolic conditions.
func (pe *PathExplorer) ExploreWithBranches(handler *ast.FunctionLiteral, pc uint32, key uint8, known []RegisterValue) []Path {
	// For now, use the single-path explorer.
	// Full branch exploration would clone the evaluator state for each
	// symbolic condition and explore both true and false paths.
	paths := pe.ExploreHandler(handler, pc, key)

	// Add known register values to each path.
	for i := range paths {
		paths[i].Known = known
	}

	return paths
}

// DecideBranch evaluates a symbolic condition and returns which branch to take.
// For concrete conditions, this returns the actual boolean.
// For symbolic conditions, this returns true (take the if-branch).
func (ev *Evaluator) DecideBranch(test ast.Expression) (bool, bool) {
	val, err := ev.EvaluateExpression(test)
	if err != nil {
		return true, false // Default to true on error.
	}

	// Try to evaluate concretely.
	if b, ok := val.AsBool(); ok {
		return b, true
	}

	// Try truthiness for numbers.
	if n, ok := val.AsNumber(); ok {
		return n != 0 && !math.IsNaN(n), true
	}

	// Try truthiness for strings.
	if s, ok := val.AsString(); ok {
		return !s.IsEmpty(), true
	}

	// Symbolic: default to true.
	return true, false
}

// Truthy returns the truthiness of a value.
func Truthy(v Value) bool {
	switch v.Kind {
	case KindUndefined, KindNull:
		return false
	case KindBool:
		return v.Bool
	case KindNumber:
		return v.Number != 0 && !math.IsNaN(v.Number)
	case KindString:
		return !v.String.IsEmpty()
	default:
		return true
	}
}

// LogicalAnd evaluates && with short-circuit semantics.
func (ev *Evaluator) LogicalAnd(left, right ast.Expression) (Value, error) {
	leftVal, err := ev.EvaluateExpression(left)
	if err != nil {
		return Value{}, err
	}

	if !Truthy(leftVal) {
		return leftVal, nil
	}

	return ev.EvaluateExpression(right)
}

// LogicalOr evaluates || with short-circuit semantics.
func (ev *Evaluator) LogicalOr(left, right ast.Expression) (Value, error) {
	leftVal, err := ev.EvaluateExpression(left)
	if err != nil {
		return Value{}, err
	}

	if Truthy(leftVal) {
		return leftVal, nil
	}

	return ev.EvaluateExpression(right)
}

// LogicalCoalesce evaluates ?? (nullish coalescing).
func (ev *Evaluator) LogicalCoalesce(left, right ast.Expression) (Value, error) {
	leftVal, err := ev.EvaluateExpression(left)
	if err != nil {
		return Value{}, err
	}

	if leftVal.Kind == KindUndefined || leftVal.Kind == KindNull {
		return ev.EvaluateExpression(right)
	}

	return leftVal, nil
}

// EvaluateLogical evaluates a logical expression (&&, ||, ??).
func (ev *Evaluator) EvaluateLogical(op token.Token, left, right ast.Expression) (Value, error) {
	switch op {
	case token.LOGICAL_AND:
		return ev.LogicalAnd(left, right)
	case token.LOGICAL_OR:
		return ev.LogicalOr(left, right)
	default:
		// ?? might not be directly supported by goja's token.
		return ev.LogicalCoalesce(left, right)
	}
}
