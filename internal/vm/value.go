package vm

// ValueKind is the kind tag for a VM value.
type ValueKind int

const (
	KindUndefined ValueKind = iota
	KindNull
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
	KindSet
	KindMap
	KindFunction
	KindSymbol
	KindNamespace
	KindSymbolic
	KindMachine
	KindRegisters
	KindRegisterSlots
	KindProgram
	KindCells
	KindCell
)

// Value is a handler value: concrete when determined by bytes, symbolic when
// dependent on registers.
type Value struct {
	Kind ValueKind

	Bool   bool
	Number float64
	String JsString
	Array  []Value
	Object []ObjectEntry
	Set    []Value
	Map    []MapEntry
	Symbol *SymbolID

	Callable *Callable

	Namespace string

	Term *Term

	Slots     Slots
	CellIndex uint32
}

type ObjectEntry struct {
	Key   string
	Value Value
}

type MapEntry struct {
	Key   Value
	Value Value
}

type SymbolID struct {
	ID int
}

type Slots int

const (
	SlotsValues Slots = iota
	SlotsTags
)

// JsString is a JavaScript string as UTF-16 code units.
type JsString struct {
	Units []uint16
}

func NewJsString(s string) JsString {
	return JsString{Units: stringToUTF16(s)}
}

func (s JsString) Text() (string, bool) {
	return utf16ToString(s.Units)
}

func (s JsString) Len() int { return len(s.Units) }

func (s JsString) IsEmpty() bool { return len(s.Units) == 0 }

func (s JsString) Unit(index int) (uint16, bool) {
	if index < 0 || index >= len(s.Units) {
		return 0, false
	}
	return s.Units[index], true
}

func (s JsString) Concat(other JsString) JsString {
	if other.IsEmpty() {
		return s
	}
	if s.IsEmpty() {
		return other
	}
	result := make([]uint16, 0, len(s.Units)+len(other.Units))
	result = append(result, s.Units...)
	result = append(result, other.Units...)
	return JsString{Units: result}
}

type Callable struct {
	Type         CallableType
	Name         string
	Func         interface{}
	This         *Value
	Scope        *Scope
	Builtin      Builtin
	StandardPath string
	Target       *Value
	BoundTarget  *Value
	BoundThis    *Value
	BoundArgs    []Value
}

type CallableType int

const (
	CallableScript CallableType = iota
	CallableArrow
	CallableBuiltin
	CallableStandard
	CallableCall
	CallableApply
	CallableBind
	CallableBound
)

type Builtin string

const (
	BuiltinNone               Builtin = ""
	BuiltinMathFloor          Builtin = "Math.floor"
	BuiltinMathCeil           Builtin = "Math.ceil"
	BuiltinMathRound          Builtin = "Math.round"
	BuiltinMathAbs            Builtin = "Math.abs"
	BuiltinMathMin            Builtin = "Math.min"
	BuiltinMathMax            Builtin = "Math.max"
	BuiltinMathPow            Builtin = "Math.pow"
	BuiltinMathSqrt           Builtin = "Math.sqrt"
	BuiltinMathRandom         Builtin = "Math.random"
	BuiltinMathLog            Builtin = "Math.log"
	BuiltinMathExp            Builtin = "Math.exp"
	BuiltinMathSin            Builtin = "Math.sin"
	BuiltinMathCos            Builtin = "Math.cos"
	BuiltinMathTan            Builtin = "Math.tan"
	BuiltinMathAtan           Builtin = "Math.atan"
	BuiltinMathAtan2          Builtin = "Math.atan2"
	BuiltinMathPI             Builtin = "Math.PI"
	BuiltinMathE              Builtin = "Math.E"
	BuiltinStringFromCharCode Builtin = "String.fromCharCode"
	BuiltinStringCharCodeAt   Builtin = "String.prototype.charCodeAt"
	BuiltinStringCharAt       Builtin = "String.prototype.charAt"
	BuiltinStringSlice        Builtin = "String.prototype.slice"
	BuiltinStringSubstring    Builtin = "String.prototype.substring"
	BuiltinStringSplit        Builtin = "String.prototype.split"
	BuiltinStringConcat       Builtin = "String.prototype.concat"
	BuiltinStringIndexOf      Builtin = "String.prototype.indexOf"
	BuiltinStringLength       Builtin = "String.prototype.length"
	BuiltinArrayPush          Builtin = "Array.prototype.push"
	BuiltinArrayPop           Builtin = "Array.prototype.pop"
	BuiltinArraySlice         Builtin = "Array.prototype.slice"
	BuiltinArrayJoin          Builtin = "Array.prototype.join"
	BuiltinArrayLength        Builtin = "Array.prototype.length"
	BuiltinArrayFrom          Builtin = "Array.from"
	BuiltinArrayIsArray       Builtin = "Array.isArray"
	BuiltinObjectKeys         Builtin = "Object.keys"
	BuiltinObjectValues       Builtin = "Object.values"
	BuiltinObjectAssign       Builtin = "Object.assign"
	BuiltinNumberIsInteger    Builtin = "Number.isInteger"
	BuiltinNumberParseInt     Builtin = "Number.parseInt"
	BuiltinNumberParseFloat   Builtin = "Number.parseFloat"
	BuiltinParseInt           Builtin = "parseInt"
	BuiltinParseFloat         Builtin = "parseFloat"
	BuiltinIsNaN              Builtin = "isNaN"
	BuiltinEncodeURI          Builtin = "encodeURI"
	BuiltinDecodeURI          Builtin = "decodeURI"
)

func (b Builtin) Path() string { return string(b) }

type Scope struct {
	Variables map[string]Value
	Outer     *Scope
}

func (s *Scope) Find(name string) (Value, bool) {
	if s == nil {
		return Value{}, false
	}
	if v, ok := s.Variables[name]; ok {
		return v, true
	}
	return s.Outer.Find(name)
}

func (s *Scope) Assign(name string, value Value) *Value {
	if s == nil {
		return &value
	}
	if _, ok := s.Variables[name]; ok {
		s.Variables[name] = value
		return nil
	}
	return s.Outer.Assign(name, value)
}

func stringToUTF16(s string) []uint16 {
	runes := []rune(s)
	result := make([]uint16, 0, len(runes))
	for _, r := range runes {
		if r <= 0xFFFF {
			result = append(result, uint16(r))
		} else {
			r -= 0x10000
			result = append(result, 0xD800|uint16(r>>10))
			result = append(result, 0xDC00|uint16(r&0x3FF))
		}
	}
	return result
}

func utf16ToString(units []uint16) (string, bool) {
	runes := make([]rune, 0, len(units))
	i := 0
	for i < len(units) {
		r := rune(units[i])
		if r >= 0xD800 && r <= 0xDBFF && i+1 < len(units) {
			lo := rune(units[i+1])
			if lo >= 0xDC00 && lo <= 0xDFFF {
				r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
				i += 2
				runes = append(runes, r)
				continue
			}
			return "", false
		}
		if r >= 0xD800 && r <= 0xDFFF {
			return "", false
		}
		runes = append(runes, r)
		i++
	}
	return string(runes), true
}

func Undefined() Value           { return Value{Kind: KindUndefined} }
func Null() Value                { return Value{Kind: KindNull} }
func BoolVal(b bool) Value       { return Value{Kind: KindBool, Bool: b} }
func NumberVal(n float64) Value  { return Value{Kind: KindNumber, Number: n} }
func StringVal(s string) Value   { return Value{Kind: KindString, String: NewJsString(s)} }
func ArrayVal(e []Value) Value   { return Value{Kind: KindArray, Array: e} }
func SymbolicVal(t Term) Value   { return Value{Kind: KindSymbolic, Term: &t} }
func MachineVal() Value          { return Value{Kind: KindMachine} }
func RegistersVal() Value        { return Value{Kind: KindRegisters} }
func ProgramVal() Value          { return Value{Kind: KindProgram} }
func CellsVal() Value            { return Value{Kind: KindCells} }
func CellVal(i uint32) Value     { return Value{Kind: KindCell, CellIndex: i} }
func NamespaceVal(p string) Value { return Value{Kind: KindNamespace, Namespace: p} }

func (v Value) IsImmutable() bool {
	switch v.Kind {
	case KindArray, KindObject, KindSet, KindMap:
		return false
	case KindFunction:
		if v.Callable == nil {
			return true
		}
		switch v.Callable.Type {
		case CallableBuiltin, CallableStandard:
			return true
		case CallableScript:
			return v.Callable.Scope == nil
		default:
			return false
		}
	default:
		return true
	}
}

func (v Value) IsSymbolic() bool { return v.Kind == KindSymbolic }

func (v Value) AsNumber() (float64, bool) {
	if v.Kind == KindNumber {
		return v.Number, true
	}
	return 0, false
}

func (v Value) AsBool() (bool, bool) {
	if v.Kind == KindBool {
		return v.Bool, true
	}
	return false, false
}

func (v Value) AsString() (JsString, bool) {
	if v.Kind == KindString {
		return v.String, true
	}
	return JsString{}, false
}
