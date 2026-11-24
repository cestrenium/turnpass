package vm

// Term is a symbolic expression that represents a value dependent on unknown
// registers.
type Term struct {
	Kind         TermKind
	Const        Constant
	Array        []Term
	Object       []ObjectTerm
	BinaryOp     BinaryOp
	BinaryLeft   *Term
	BinaryRight  *Term
	UnaryOp      UnaryOp
	UnaryExpr    *Term
	Field        string
	Global       string
	ClosurePC    uint32
	ClosureKey   uint8
	ClosureParams []uint8
	ClosureArity uint8
	CellIndex    uint32
	Opaque       string
}

type ObjectTerm struct {
	Key   string
	Value Term
}

type TermKind int

const (
	TermConst TermKind = iota
	TermArray
	TermObject
	TermBinary
	TermUnary
	TermField
	TermGlobal
	TermClosure
	TermCells
	TermCell
	TermOpaque
)

type Constant struct {
	Kind   ConstantKind
	Bool   bool
	Number float64
	String string
}

type ConstantKind int

const (
	ConstUndefined ConstantKind = iota
	ConstNull
	ConstBool
	ConstNumber
	ConstString
)

type BinaryOp int

const (
	BinAdd BinaryOp = iota
	BinSub
	BinMul
	BinDiv
	BinMod
	BinBitAnd
	BinBitOr
	BinBitXor
	BinShiftLeft
	BinShiftRight
	BinUnsignedShiftRight
	BinLessThan
	BinGreaterThan
	BinLessEqual
	BinGreaterEqual
	BinEquals
	BinNotEquals
	BinStrictEquals
	BinStrictNotEquals
	BinLogicalAnd
	BinLogicalOr
	BinNullishCoalescing
	BinExponent
)

type UnaryOp int

const (
	UnaryNeg UnaryOp = iota
	UnaryNot
	UnaryBitNot
	UnaryTypeof
	UnaryVoid
)

func ConstUndefinedVal() Constant       { return Constant{Kind: ConstUndefined} }
func ConstNullVal() Constant            { return Constant{Kind: ConstNull} }
func ConstBoolVal(b bool) Constant      { return Constant{Kind: ConstBool, Bool: b} }
func ConstNumberVal(n float64) Constant { return Constant{Kind: ConstNumber, Number: n} }
func ConstStringVal(s string) Constant  { return Constant{Kind: ConstString, String: s} }

func TermConstVal(c Constant) Term          { return Term{Kind: TermConst, Const: c} }
func TermArrayVal(e []Term) Term            { return Term{Kind: TermArray, Array: e} }
func TermObjectVal(p []ObjectTerm) Term     { return Term{Kind: TermObject, Object: p} }
func TermBinaryVal(op BinaryOp, l, r Term) Term {
	return Term{Kind: TermBinary, BinaryOp: op, BinaryLeft: &l, BinaryRight: &r}
}
func TermUnaryVal(op UnaryOp, e Term) Term {
	return Term{Kind: TermUnary, UnaryOp: op, UnaryExpr: &e}
}
func TermFieldVal(f string) Term    { return Term{Kind: TermField, Field: f} }
func TermGlobalVal(p string) Term   { return Term{Kind: TermGlobal, Global: p} }
func TermOpaqueVal(t string) Term   { return Term{Kind: TermOpaque, Opaque: t} }
func TermCellsVal() Term            { return Term{Kind: TermCells} }
func TermCellVal(i uint32) Term     { return Term{Kind: TermCell, CellIndex: i} }

func (v Value) Expr() Term {
	switch v.Kind {
	case KindUndefined:
		return TermConstVal(ConstUndefinedVal())
	case KindNull:
		return TermConstVal(ConstNullVal())
	case KindBool:
		return TermConstVal(ConstBoolVal(v.Bool))
	case KindNumber:
		return TermConstVal(ConstNumberVal(v.Number))
	case KindString:
		if text, ok := v.String.Text(); ok {
			return TermConstVal(ConstStringVal(text))
		}
		units := make([]string, len(v.String.Units))
		for i, u := range v.String.Units {
			units[i] = uint16ToString(u)
		}
		return TermOpaqueVal("String.fromCharCode(" + joinStrings(units, ", ") + ")")
	case KindArray:
		elements := make([]Term, len(v.Array))
		for i, e := range v.Array {
			elements[i] = e.Expr()
		}
		return TermArrayVal(elements)
	case KindObject:
		props := make([]ObjectTerm, len(v.Object))
		for i, e := range v.Object {
			props[i] = ObjectTerm{Key: e.Key, Value: e.Value.Expr()}
		}
		return TermObjectVal(props)
	case KindSymbolic:
		if v.Term != nil {
			return *v.Term
		}
		return TermOpaqueVal("<nil symbolic>")
	case KindCells:
		return TermCellsVal()
	case KindCell:
		return TermCellVal(v.CellIndex)
	case KindFunction:
		if v.Callable == nil {
			return TermOpaqueVal("function")
		}
		switch v.Callable.Type {
		case CallableBuiltin:
			return TermGlobalVal(v.Callable.Builtin.Path())
		case CallableStandard:
			return TermGlobalVal(v.Callable.StandardPath)
		default:
			return TermOpaqueVal("function")
		}
	case KindSet:
		return TermOpaqueVal("set")
	case KindMap:
		return TermOpaqueVal("map")
	case KindSymbol:
		return TermOpaqueVal("symbol")
	case KindNamespace:
		if v.Namespace == "" {
			return TermGlobalVal("globalThis")
		}
		return TermGlobalVal(v.Namespace)
	default:
		return TermOpaqueVal("machine internals")
	}
}

func uint16ToString(n uint16) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for _, p := range parts[1:] {
		result += sep + p
	}
	return result
}
