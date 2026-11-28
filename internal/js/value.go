// Package js provides JSON value types used by the expression evaluator
// and payload builder. These mirror cfsolve's JsValue type.
package js

import "fmt"

// Value is a JSON value: null, bool, number, string, array, or object.
type Value interface {
	jsonValue()
}

type Null struct{}

func (Null) jsonValue() {}

type Bool bool

func (Bool) jsonValue() {}

type Number float64

func (Number) jsonValue() {}

type String string

func (String) jsonValue() {}

type Array []Value

func (Array) jsonValue() {}

type Object map[string]Value

func (Object) jsonValue() {}

func NullVal() Value            { return Null{} }
func BoolVal(b bool) Value      { return Bool(b) }
func NumberVal(n float64) Value { return Number(n) }
func StringVal(s string) Value  { return String(s) }

func Truthy(v Value) bool {
	switch val := v.(type) {
	case Null:
		return false
	case Bool:
		return bool(val)
	case Number:
		return val != 0
	case String:
		return len(val) > 0
	case Array:
		return true
	case Object:
		return true
	case nil:
		return false
	}
	return false
}

func ToNumber(v Value) float64 {
	switch val := v.(type) {
	case Null:
		return 0
	case Bool:
		if val {
			return 1
		}
		return 0
	case Number:
		return float64(val)
	case String:
		if f, err := fmt.Sscanf(string(val), "%g", new(float64)); f == 1 && err == nil {
			return *new(float64)
		}
		// Try simpler parse
		var f2 float64
		if _, err := fmt.Sscanf(string(val), "%f", &f2); err == nil {
			return f2
		}
		return 0
	}
	return 0
}

func ToString(v Value) string {
	switch val := v.(type) {
	case Null:
		return "null"
	case Bool:
		if val {
			return "true"
		}
		return "false"
	case Number:
		return fmt.Sprintf("%g", float64(val))
	case String:
		return string(val)
	case Array:
		var parts []string
		for _, elem := range val {
			if _, ok := elem.(Null); ok {
				parts = append(parts, "")
			} else {
				parts = append(parts, ToString(elem))
			}
		}
		return joinStrings(parts, ",")
	case Object:
		return "[object Object]"
	case nil:
		return ""
	}
	return ""
}

func Stringify(v Value) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case Null:
		return "null"
	case Bool:
		if val {
			return "true"
		}
		return "false"
	case Number:
		return fmt.Sprintf("%g", float64(val))
	case String:
		return quoteJSON(string(val))
	case Array:
		var parts []string
		for _, elem := range val {
			if elem == nil {
				parts = append(parts, "null")
			} else {
				parts = append(parts, Stringify(elem))
			}
		}
		return "[" + joinStrings(parts, ",") + "]"
	case Object:
		var parts []string
		for k, v := range val {
			if v == nil {
				parts = append(parts, quoteJSON(k)+":null")
			} else {
				parts = append(parts, quoteJSON(k)+":"+Stringify(v))
			}
		}
		return "{" + joinStrings(parts, ",") + "}"
	}
	return ""
}

func quoteJSON(s string) string {
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for _, c := range []byte(s) {
		switch c {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			if c < 0x20 {
				b = append(b, []byte(fmt.Sprintf("\\u%04x", c))...)
			} else {
				b = append(b, c)
			}
		}
	}
	b = append(b, '"')
	return string(b)
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += sep + parts[i]
	}
	return result
}
