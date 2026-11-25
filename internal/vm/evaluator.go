package vm

import (
	"fmt"
	"math"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/token"
)

// Evaluator evaluates JavaScript expressions symbolically over program bytes.
// It computes byte-dependent values and leaves register-dependent values
// symbolic.
type Evaluator struct {
	Session  *Session
	Program  []byte
	PC       uint32
	Key      uint8
	Fields   map[string]Value
	Scope    *Scope
	Effects  []Effect
	Branches *BranchState
}

// BranchState tracks symbolic branch decisions during path exploration.
type BranchState struct {
	Decisions []bool // true = take if-branch, false = take else-branch
	Decided   int    // number of decisions consumed
}

// NewEvaluator creates an Evaluator for a handler invocation.
func NewEvaluator(session *Session, program []byte, pc uint32, key uint8, fields map[string]Value) *Evaluator {
	return &Evaluator{
		Session:  session,
		Program:  program,
		PC:       pc,
		Key:      key,
		Fields:   fields,
		Scope:    &Scope{Variables: make(map[string]Value)},
		Effects:  make([]Effect, 0),
		Branches: &BranchState{},
	}
}

// EvaluateExpression evaluates an AST expression and returns its Value.
func (ev *Evaluator) EvaluateExpression(expr ast.Expression) (Value, error) {
	switch e := expr.(type) {
	case *ast.NumberLiteral:
		return NumberVal(toFloat64(e.Value)), nil

	case *ast.StringLiteral:
		return StringVal(string(e.Value)), nil

	case *ast.BooleanLiteral:
		return BoolVal(e.Value), nil

	case *ast.NullLiteral:
		return Null(), nil

	case *ast.Identifier:
		return ev.lookup(string(e.Name))

	case *ast.ThisExpression:
		// 'this' inside a handler is the machine instance.
		return MachineVal(), nil

	case *ast.BinaryExpression:
		return ev.evaluateBinary(e)

	case *ast.UnaryExpression:
		return ev.evaluateUnary(e)

	case *ast.AssignExpression:
		return ev.evaluateAssign(e)

	case *ast.DotExpression:
		return ev.evaluateMember(e)

	case *ast.BracketExpression:
		return ev.evaluateBracket(e)

	case *ast.CallExpression:
		return ev.evaluateCall(e)

	case *ast.ConditionalExpression:
		return ev.evaluateConditional(e)

	case *ast.SequenceExpression:
		return ev.evaluateSequence(e)

	case *ast.ArrayLiteral:
		return ev.evaluateArray(e)

	case *ast.ObjectLiteral:
		return ev.evaluateObject(e)

	case *ast.FunctionLiteral:
		return ev.evaluateFunctionLiteral(e), nil

	case *ast.NewExpression:
		return ev.evaluateNew(e)

		// goja doesn't have ParenthesizedExpression - parenthesized expressions
		// are handled by the parser transparently.
	}

	return SymbolicVal(TermOpaqueVal(fmt.Sprintf("unsupported expression: %T", expr))), nil
}

// lookup finds a variable in the scope chain or session bindings.
func (ev *Evaluator) lookup(name string) (Value, error) {
	if v, ok := ev.Scope.Find(name); ok {
		return v, nil
	}
	if v, ok := ev.Session.Bindings[name]; ok {
		return v, nil
	}
	// Check for known globals.
	switch name {
	case "Math":
		return NamespaceVal("Math"), nil
	case "String":
		return NamespaceVal("String"), nil
	case "Array":
		return NamespaceVal("Array"), nil
	case "Object":
		return NamespaceVal("Object"), nil
	case "Number":
		return NamespaceVal("Number"), nil
	case "parseInt":
		return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinParseInt}), nil
	case "parseFloat":
		return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinParseFloat}), nil
	case "isNaN":
		return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinIsNaN}), nil
	case "undefined":
		return Undefined(), nil
	case "NaN":
		return NumberVal(math.NaN()), nil
	case "Infinity":
		return NumberVal(math.Inf(1)), nil
	}
	return Undefined(), nil
}

// evaluateBinary evaluates a binary expression.
func (ev *Evaluator) evaluateBinary(e *ast.BinaryExpression) (Value, error) {
	left, err := ev.EvaluateExpression(e.Left)
	if err != nil {
		return Value{}, err
	}
	right, err := ev.EvaluateExpression(e.Right)
	if err != nil {
		return Value{}, err
	}
	return ev.binaryOp(e.Operator, left, right), nil
}

// binaryOp applies a binary operator to two values.
func (ev *Evaluator) binaryOp(op token.Token, left, right Value) Value {
	// Try numeric operations first.
	leftNum, leftIsNum := left.AsNumber()
	rightNum, rightIsNum := right.AsNumber()

	if leftIsNum && rightIsNum {
		switch op {
		case token.PLUS:
			return NumberVal(leftNum + rightNum)
		case token.MINUS:
			return NumberVal(leftNum - rightNum)
		case token.MULTIPLY:
			return NumberVal(leftNum * rightNum)
		case token.SLASH:
			return NumberVal(leftNum / rightNum)
		case token.REMAINDER:
			return NumberVal(math.Mod(leftNum, rightNum))
		case token.AND:
			return NumberVal(float64(int32(leftNum) & int32(rightNum)))
		case token.OR:
			return NumberVal(float64(int32(leftNum) | int32(rightNum)))
		case token.EXCLUSIVE_OR:
			return NumberVal(float64(int32(leftNum) ^ int32(rightNum)))
		case token.SHIFT_LEFT:
			return NumberVal(float64(int32(leftNum) << (uint32(rightNum) & 31)))
		case token.SHIFT_RIGHT:
			return NumberVal(float64(int32(leftNum) >> (uint32(rightNum) & 31)))
		case token.UNSIGNED_SHIFT_RIGHT:
			return NumberVal(float64(uint32(leftNum) >> (uint32(rightNum) & 31)))
		case token.LESS:
			return BoolVal(leftNum < rightNum)
		case token.GREATER:
			return BoolVal(leftNum > rightNum)
		case token.LESS_OR_EQUAL:
			return BoolVal(leftNum <= rightNum)
		case token.GREATER_OR_EQUAL:
			return BoolVal(leftNum >= rightNum)
		case token.EQUAL:
			return BoolVal(leftNum == rightNum)
		case token.NOT_EQUAL:
			return BoolVal(leftNum != rightNum)
		case token.STRICT_EQUAL:
			return BoolVal(leftNum == rightNum)
		case token.STRICT_NOT_EQUAL:
			return BoolVal(leftNum != rightNum)
		case token.EXPONENT:
			return NumberVal(math.Pow(leftNum, rightNum))
		}
	}

	// String concatenation.
	if op == token.PLUS {
		if leftStr, ok := left.AsString(); ok {
			if rightStr, ok := right.AsString(); ok {
				return Value{Kind: KindString, String: leftStr.Concat(rightStr)}
			}
		}
	}

	// Symbolic result for non-numeric operations.
	return SymbolicVal(TermBinaryVal(
		tokenToBinaryOp(op),
		left.Expr(),
		right.Expr(),
	))
}

// tokenToBinaryOp converts a goja token to a BinaryOp.
func tokenToBinaryOp(op token.Token) BinaryOp {
	switch op {
	case token.PLUS:
		return BinAdd
	case token.MINUS:
		return BinSub
	case token.MULTIPLY:
		return BinMul
	case token.SLASH:
		return BinDiv
	case token.REMAINDER:
		return BinMod
	case token.AND:
		return BinBitAnd
	case token.OR:
		return BinBitOr
	case token.EXCLUSIVE_OR:
		return BinBitXor
	case token.SHIFT_LEFT:
		return BinShiftLeft
	case token.SHIFT_RIGHT:
		return BinShiftRight
	case token.UNSIGNED_SHIFT_RIGHT:
		return BinUnsignedShiftRight
	case token.LESS:
		return BinLessThan
	case token.GREATER:
		return BinGreaterThan
	case token.LESS_OR_EQUAL:
		return BinLessEqual
	case token.GREATER_OR_EQUAL:
		return BinGreaterEqual
	case token.EQUAL:
		return BinEquals
	case token.NOT_EQUAL:
		return BinNotEquals
	case token.STRICT_EQUAL:
		return BinStrictEquals
	case token.STRICT_NOT_EQUAL:
		return BinStrictNotEquals
	case token.LOGICAL_AND:
		return BinLogicalAnd
	case token.LOGICAL_OR:
		return BinLogicalOr
	case token.EXPONENT:
		return BinExponent
	default:
		return BinAdd
	}
}

// evaluateUnary evaluates a unary expression.
func (ev *Evaluator) evaluateUnary(e *ast.UnaryExpression) (Value, error) {
	operand, err := ev.EvaluateExpression(e.Operand)
	if err != nil {
		return Value{}, err
	}

	switch e.Operator {
	case token.MINUS:
		if n, ok := operand.AsNumber(); ok {
			return NumberVal(-n), nil
		}
		return SymbolicVal(TermUnaryVal(UnaryNeg, operand.Expr())), nil
	case token.NOT:
		if b, ok := operand.AsBool(); ok {
			return BoolVal(!b), nil
		}
		return SymbolicVal(TermUnaryVal(UnaryNot, operand.Expr())), nil
	case token.BITWISE_NOT:
		if n, ok := operand.AsNumber(); ok {
			return NumberVal(float64(^int32(n))), nil
		}
		return SymbolicVal(TermUnaryVal(UnaryBitNot, operand.Expr())), nil
	case token.TYPEOF:
		return StringVal(typeofString(operand)), nil
	case token.VOID:
		return Undefined(), nil
	}

	return SymbolicVal(TermOpaqueVal(fmt.Sprintf("unary %v", e.Operator))), nil
}

// typeofString returns the JavaScript typeof string for a value.
func typeofString(v Value) string {
	switch v.Kind {
	case KindUndefined:
		return "undefined"
	case KindNull:
		return "object" // JS quirk
	case KindBool:
		return "boolean"
	case KindNumber:
		return "number"
	case KindString:
		return "string"
	case KindFunction:
		return "function"
	default:
		return "object"
	}
}

// evaluateAssign evaluates an assignment expression.
func (ev *Evaluator) evaluateAssign(e *ast.AssignExpression) (Value, error) {
	if e.Operator != token.ASSIGN {
		// Compound assignment (+=, -=, etc.)
		old, err := ev.EvaluateExpression(e.Left)
		if err != nil {
			return Value{}, err
		}
		right, err := ev.EvaluateExpression(e.Right)
		if err != nil {
			return Value{}, err
		}
		op := compoundOp(e.Operator)
		result := ev.binaryOp(op, old, right)
		ev.assignTo(e.Left, result)
		return result, nil
	}

	// Simple assignment.
	value, err := ev.EvaluateExpression(e.Right)
	if err != nil {
		return Value{}, err
	}
	ev.assignTo(e.Left, value)
	return value, nil
}

// compoundOp returns the binary operator for a compound assignment.
func compoundOp(op token.Token) token.Token {
	switch op {
	case token.ADD_ASSIGN:
		return token.PLUS
	case token.SUBTRACT_ASSIGN:
		return token.MINUS
	case token.MULTIPLY_ASSIGN:
		return token.MULTIPLY
	case token.QUOTIENT_ASSIGN:
		return token.SLASH
	case token.REMAINDER_ASSIGN:
		return token.REMAINDER
	case token.AND_ASSIGN:
		return token.AND
	case token.OR_ASSIGN:
		return token.OR
	case token.EXCLUSIVE_OR_ASSIGN:
		return token.EXCLUSIVE_OR
	case token.SHIFT_LEFT_ASSIGN:
		return token.SHIFT_LEFT
	case token.SHIFT_RIGHT_ASSIGN:
		return token.SHIFT_RIGHT
	case token.UNSIGNED_SHIFT_RIGHT_ASSIGN:
		return token.UNSIGNED_SHIFT_RIGHT
	case token.EXPONENT_ASSIGN:
		return token.EXPONENT
	default:
		return op
	}
}

// assignTo assigns a value to an assignment target.
func (ev *Evaluator) assignTo(target ast.Expression, value Value) {
	switch t := target.(type) {
	case *ast.Identifier:
		// In sloppy mode, assigning to an undeclared variable creates it.
		if ret := ev.Scope.Assign(string(t.Name), value); ret != nil {
			ev.Scope.Variables[string(t.Name)] = value
		}
	case *ast.DotExpression:
		// this.field = value
		if _, isThis := t.Left.(*ast.ThisExpression); isThis {
			fieldName := string(t.Identifier.Name)
			ev.Fields[fieldName] = value
			ev.Effects = append(ev.Effects, Effect{
				Kind:  EffectWriteField,
				Field: fieldName,
				Value: value.Expr(),
			})
		}
	case *ast.BracketExpression:
		// this[field] = value or array[index] = value
		ev.assignToBracket(t, value)
	}
}

// evaluateMember evaluates a dot member access (e.g., this.field, obj.prop).
func (ev *Evaluator) evaluateMember(e *ast.DotExpression) (Value, error) {
	// this.field
	if _, isThis := e.Left.(*ast.ThisExpression); isThis {
		fieldName := string(e.Identifier.Name)
		if v, ok := ev.Fields[fieldName]; ok {
			return v, nil
		}
		// Check for known register file members.
		member := MemberOf(fieldName)
		switch member {
		case MemberPc:
			return NumberVal(float64(ev.PC)), nil
		case MemberKey:
			return NumberVal(float64(ev.Key)), nil
		case MemberProgram:
			return ProgramVal(), nil
		case MemberValues:
			return Value{Kind: KindRegisterSlots, Slots: SlotsValues}, nil
		case MemberTags:
			return Value{Kind: KindRegisterSlots, Slots: SlotsTags}, nil
		case MemberRegisters:
			return RegistersVal(), nil
		}
		return Undefined(), nil
	}

	// Evaluate the object.
	obj, err := ev.EvaluateExpression(e.Left)
	if err != nil {
		return Value{}, err
	}

	// Access the property.
	return ev.getProperty(obj, string(e.Identifier.Name)), nil
}

// evaluateBracket evaluates a bracket member access (e.g., arr[index]).
func (ev *Evaluator) evaluateBracket(e *ast.BracketExpression) (Value, error) {
	// Program byte access: program[pc]
	if _, isProgram := e.Left.(*ast.Identifier); isProgram {
		leftName := string(e.Left.(*ast.Identifier).Name)
		if leftName == "program" || ev.isProgramRef(e.Left) {
			index, err := ev.EvaluateExpression(e.Member)
			if err != nil {
				return Value{}, err
			}
			if n, ok := index.AsNumber(); ok {
				idx := int(n)
				if idx >= 0 && idx < len(ev.Program) {
					return NumberVal(float64(ev.Program[idx])), nil
				}
			}
		}
	}

	// Evaluate the object and index.
	obj, err := ev.EvaluateExpression(e.Left)
	if err != nil {
		return Value{}, err
	}
	index, err := ev.EvaluateExpression(e.Member)
	if err != nil {
		return Value{}, err
	}
	return ev.getElement(obj, index), nil
}

// isProgramRef checks if an expression refers to the program.
func (ev *Evaluator) isProgramRef(expr ast.Expression) bool {
	if id, ok := expr.(*ast.Identifier); ok {
		_, found := ev.Session.Bindings[string(id.Name)]
		return found
	}
	return false
}

// getProperty gets a property from a value.
func (ev *Evaluator) getProperty(obj Value, name string) Value {
	switch obj.Kind {
	case KindNamespace:
		switch obj.Namespace {
		case "Math":
			switch name {
			case "floor":
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinMathFloor})
			case "ceil":
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinMathCeil})
			case "round":
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinMathRound})
			case "abs":
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinMathAbs})
			case "min":
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinMathMin})
			case "max":
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinMathMax})
			case "pow":
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinMathPow})
			case "sqrt":
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinMathSqrt})
			case "random":
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinMathRandom})
			case "PI":
				return NumberVal(math.Pi)
			case "E":
				return NumberVal(math.E)
			}
		case "String":
			if name == "fromCharCode" {
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinStringFromCharCode})
			}
		case "Array":
			if name == "isArray" {
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinArrayIsArray})
			}
		case "Object":
			if name == "keys" {
				return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinObjectKeys})
			}
		}
	case KindString:
		switch name {
		case "length":
			return NumberVal(float64(obj.String.Len()))
		case "charCodeAt":
			return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinStringCharCodeAt})
		case "charAt":
			return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinStringCharAt})
		case "slice":
			return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinStringSlice})
		case "split":
			return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinStringSplit})
		}
	case KindArray:
		if name == "length" {
			return NumberVal(float64(len(obj.Array)))
		}
		if name == "push" {
			return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinArrayPush})
		}
		if name == "pop" {
			return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinArrayPop})
		}
		if name == "slice" {
			return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinArraySlice})
		}
		if name == "join" {
			return FunctionVal(Callable{Type: CallableBuiltin, Builtin: BuiltinArrayJoin})
		}
	}

	return SymbolicVal(TermFieldVal(name))
}

// getElement gets an element from a value by index.
func (ev *Evaluator) getElement(obj Value, index Value) Value {
	if n, ok := index.AsNumber(); ok {
		idx := int(n)
		switch obj.Kind {
		case KindArray:
			if idx >= 0 && idx < len(obj.Array) {
				return obj.Array[idx]
			}
		case KindString:
			if u, ok := obj.String.Unit(idx); ok {
				return NumberVal(float64(u))
			}
		}
	}
	return SymbolicVal(TermOpaqueVal("element access"))
}

// evaluateCall evaluates a function call.
func (ev *Evaluator) evaluateCall(e *ast.CallExpression) (Value, error) {
	// Evaluate the callee.
	callee, err := ev.EvaluateExpression(e.Callee)
	if err != nil {
		return Value{}, err
	}

	// Evaluate arguments.
	args := make([]Value, 0, len(e.ArgumentList))
	for _, arg := range e.ArgumentList {
		v, err := ev.EvaluateExpression(arg)
		if err != nil {
			return Value{}, err
		}
		args = append(args, v)
	}

	return ev.callFunction(callee, args)
}

// callFunction calls a function value with arguments.
func (ev *Evaluator) callFunction(callee Value, args []Value) (Value, error) {
	if callee.Kind != KindFunction || callee.Callable == nil {
		return SymbolicVal(TermOpaqueVal("call non-function")), nil
	}

	switch callee.Callable.Type {
	case CallableBuiltin:
		return ev.callBuiltin(callee.Callable.Builtin, args), nil
	case CallableScript:
		// Execute the function's body in a new scope.
		fn, ok := callee.Callable.Func.(*ast.FunctionLiteral)
		if !ok {
			return SymbolicVal(TermOpaqueVal("call non-literal")), nil
		}
		return ev.callScript(fn, args)
	}

	return SymbolicVal(TermOpaqueVal("call")), nil
}

// callBuiltin executes a builtin function.
func (ev *Evaluator) callBuiltin(builtin Builtin, args []Value) Value {
	getNum := func(i int) (float64, bool) {
		if i < len(args) {
			return args[i].AsNumber()
		}
		return 0, false
	}

	switch builtin {
	case BuiltinMathFloor:
		if n, ok := getNum(0); ok {
			return NumberVal(math.Floor(n))
		}
	case BuiltinMathCeil:
		if n, ok := getNum(0); ok {
			return NumberVal(math.Ceil(n))
		}
	case BuiltinMathRound:
		if n, ok := getNum(0); ok {
			return NumberVal(math.Round(n))
		}
	case BuiltinMathAbs:
		if n, ok := getNum(0); ok {
			return NumberVal(math.Abs(n))
		}
	case BuiltinMathMin:
		if a, ok := getNum(0); ok {
			if b, ok := getNum(1); ok {
				return NumberVal(math.Min(a, b))
			}
		}
	case BuiltinMathMax:
		if a, ok := getNum(0); ok {
			if b, ok := getNum(1); ok {
				return NumberVal(math.Max(a, b))
			}
		}
	case BuiltinMathPow:
		if a, ok := getNum(0); ok {
			if b, ok := getNum(1); ok {
				return NumberVal(math.Pow(a, b))
			}
		}
	case BuiltinMathSqrt:
		if n, ok := getNum(0); ok {
			return NumberVal(math.Sqrt(n))
		}
	case BuiltinStringFromCharCode:
		// Build a string from char codes.
		units := make([]uint16, 0, len(args))
		for _, arg := range args {
			if n, ok := arg.AsNumber(); ok {
				units = append(units, uint16(int(n)&0xFFFF))
			}
		}
		return Value{Kind: KindString, String: JsString{Units: units}}
	case BuiltinStringCharCodeAt:
		if len(args) >= 2 {
			if s, ok := args[0].AsString(); ok {
				if idx, ok := args[1].AsNumber(); ok {
					if u, ok := s.Unit(int(idx)); ok {
						return NumberVal(float64(u))
					}
				}
			}
		}
	case BuiltinParseInt:
		if len(args) >= 1 {
			if s, ok := args[0].AsString(); ok {
				if text, ok := s.Text(); ok {
					var n int
					_, _ = fmt.Sscanf(text, "%d", &n)
					return NumberVal(float64(n))
				}
			}
		}
	case BuiltinIsNaN:
		if n, ok := getNum(0); ok {
			return BoolVal(math.IsNaN(n))
		}
	case BuiltinArrayPush:
		if len(args) >= 1 {
			if args[0].Kind == KindArray {
				// Push remaining args.
				args[0].Array = append(args[0].Array, args[1:]...)
				return NumberVal(float64(len(args[0].Array)))
			}
		}
	case BuiltinArrayIsArray:
		if len(args) >= 1 {
			return BoolVal(args[0].Kind == KindArray)
		}
	}

	return SymbolicVal(TermOpaqueVal(fmt.Sprintf("builtin %s", builtin)))
}

// callScript executes a script function literal.
func (ev *Evaluator) callScript(fn *ast.FunctionLiteral, args []Value) (Value, error) {
	if fn.Body == nil {
		return Undefined(), nil
	}

	// Create a new scope with the function's parameters.
	oldScope := ev.Scope
	newScope := &Scope{
		Variables: make(map[string]Value),
		Outer:     oldScope,
	}

	// Bind parameters.
	if fn.ParameterList != nil {
		for i, param := range fn.ParameterList.List {
			if i < len(args) {
				name := paramName(param)
				if name != "" {
					newScope.Variables[name] = args[i]
				}
			}
		}
	}
	ev.Scope = newScope

	// Execute the body.
	var result Value = Undefined()
	for _, stmt := range fn.Body.List {
		flow, retVal, err := ev.ExecuteStatement(stmt)
		if err != nil {
			ev.Scope = oldScope
			return Value{}, err
		}
		if flow == FlowReturn {
			result = retVal
			break
		}
	}

	ev.Scope = oldScope
	return result, nil
}

// paramName extracts the name of a function parameter.
func paramName(param *ast.Binding) string {
	if param == nil {
		return ""
	}
	if id, ok := param.Target.(*ast.Identifier); ok {
		return string(id.Name)
	}
	return ""
}

// assignToBracket handles bracket assignment.
func (ev *Evaluator) assignToBracket(e *ast.BracketExpression, value Value) {
	// Array element assignment: arr[index] = value
	if obj, err := ev.EvaluateExpression(e.Left); err == nil {
		if idx, err := ev.EvaluateExpression(e.Member); err == nil {
			if obj.Kind == KindArray {
				if n, ok := idx.AsNumber(); ok {
					i := int(n)
					if i >= 0 && i < len(obj.Array) {
						obj.Array[i] = value
					}
				}
			}
		}
	}
}

// evaluateConditional evaluates a ternary conditional.
func (ev *Evaluator) evaluateConditional(e *ast.ConditionalExpression) (Value, error) {
	test, err := ev.EvaluateExpression(e.Test)
	if err != nil {
		return Value{}, err
	}

	// Try to evaluate the condition concretely.
	if b, ok := test.AsBool(); ok {
		if b {
			return ev.EvaluateExpression(e.Consequent)
		}
		return ev.EvaluateExpression(e.Alternate)
	}

	// Symbolic condition: explore both paths.
	// For now, take the first branch.
	return ev.EvaluateExpression(e.Consequent)
}

// evaluateSequence evaluates a sequence expression (a, b, c).
func (ev *Evaluator) evaluateSequence(e *ast.SequenceExpression) (Value, error) {
	var result Value = Undefined()
	for _, expr := range e.Sequence {
		var err error
		result, err = ev.EvaluateExpression(expr)
		if err != nil {
			return Value{}, err
		}
	}
	return result, nil
}

// evaluateArray evaluates an array literal.
func (ev *Evaluator) evaluateArray(e *ast.ArrayLiteral) (Value, error) {
	elements := make([]Value, 0, len(e.Value))
	for _, expr := range e.Value {
		v, err := ev.EvaluateExpression(expr)
		if err != nil {
			return Value{}, err
		}
		elements = append(elements, v)
	}
	return ArrayVal(elements), nil
}

// evaluateObject evaluates an object literal.
func (ev *Evaluator) evaluateObject(e *ast.ObjectLiteral) (Value, error) {
	props := make([]ObjectEntry, 0, len(e.Value))
	for _, prop := range e.Value {
		if kp, ok := prop.(*ast.PropertyKeyed); ok {
			key := propertyKey(kp.Key)
			val, err := ev.EvaluateExpression(kp.Value)
			if err != nil {
				return Value{}, err
			}
			props = append(props, ObjectEntry{Key: key, Value: val})
		}
	}
	return Value{Kind: KindObject, Object: props}, nil
}

// propertyKey extracts the key from a property.
func propertyKey(key ast.Expression) string {
	if id, ok := key.(*ast.Identifier); ok {
		return string(id.Name)
	}
	if lit, ok := key.(*ast.StringLiteral); ok {
		return string(lit.Value)
	}
	if num, ok := key.(*ast.NumberLiteral); ok {
		if n, ok := num.Value.(float64); ok {
			return fmt.Sprintf("%v", n)
		}
	}
	return ""
}

// evaluateFunctionLiteral creates a function value from a function literal.
func (ev *Evaluator) evaluateFunctionLiteral(e *ast.FunctionLiteral) Value {
	return Value{
		Kind: KindFunction,
		Callable: &Callable{
			Type:  CallableScript,
			Func:  e,
			Scope: ev.Scope,
		},
	}
}

// evaluateNew evaluates a new expression.
func (ev *Evaluator) evaluateNew(e *ast.NewExpression) (Value, error) {
	// For now, return an empty object.
	return Value{Kind: KindObject, Object: []ObjectEntry{}}, nil
}

// FlowKind indicates how a statement completed.
type FlowKind int

const (
	FlowNormal FlowKind = iota
	FlowReturn
	FlowBreak
	FlowContinue
	FlowThrow
)

// ExecuteStatement executes a statement and returns the flow control.
func (ev *Evaluator) ExecuteStatement(stmt ast.Statement) (FlowKind, Value, error) {
	switch s := stmt.(type) {
	case *ast.ExpressionStatement:
		_, err := ev.EvaluateExpression(s.Expression)
		return FlowNormal, Undefined(), err

	case *ast.BlockStatement:
		for _, bs := range s.List {
			flow, val, err := ev.ExecuteStatement(bs)
			if err != nil {
				return flow, val, err
			}
			if flow != FlowNormal {
				return flow, val, nil
			}
		}
		return FlowNormal, Undefined(), nil

	case *ast.ReturnStatement:
		if s.Argument != nil {
			val, err := ev.EvaluateExpression(s.Argument)
			if err != nil {
				return FlowThrow, Undefined(), err
			}
			return FlowReturn, val, nil
		}
		return FlowReturn, Undefined(), nil

	case *ast.IfStatement:
		test, err := ev.EvaluateExpression(s.Test)
		if err != nil {
			return FlowThrow, Undefined(), err
		}
		if b, ok := test.AsBool(); ok {
			if b {
				return ev.ExecuteStatement(s.Consequent)
			}
			if s.Alternate != nil {
				return ev.ExecuteStatement(s.Alternate)
			}
		} else {
			// Symbolic condition: take the consequent.
			return ev.ExecuteStatement(s.Consequent)
		}
		return FlowNormal, Undefined(), nil

	case *ast.WhileStatement:
		// Evaluate the while loop body (limited iterations for safety).
		for i := 0; i < 10000; i++ {
			test, err := ev.EvaluateExpression(s.Test)
			if err != nil {
				return FlowThrow, Undefined(), err
			}
			if b, ok := test.AsBool(); ok {
				if !b {
					break
				}
			} else {
				break // Symbolic condition: stop.
			}
			flow, _, err := ev.ExecuteStatement(s.Body)
			if err != nil {
				return flow, Undefined(), err
			}
			if flow == FlowBreak {
				break
			}
			if flow == FlowReturn {
				return flow, Undefined(), nil
			}
		}
		return FlowNormal, Undefined(), nil

	case *ast.BranchStatement:
		if s.Token == token.BREAK {
			return FlowBreak, Undefined(), nil
		}
		return FlowContinue, Undefined(), nil

	case *ast.ThrowStatement:
		val, err := ev.EvaluateExpression(s.Argument)
		if err != nil {
			return FlowThrow, Undefined(), err
		}
		return FlowThrow, val, nil

	case *ast.VariableStatement:
		for _, decl := range s.List {
			if decl.Initializer != nil {
				val, err := ev.EvaluateExpression(decl.Initializer)
				if err != nil {
					return FlowThrow, Undefined(), err
				}
				name := paramName(decl)
				if name != "" {
					ev.Scope.Variables[name] = val
				}
			}
		}
		return FlowNormal, Undefined(), nil

	case *ast.EmptyStatement:
		return FlowNormal, Undefined(), nil
	}

	return FlowNormal, Undefined(), nil
}
