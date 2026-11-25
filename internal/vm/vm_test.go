package vm

import (
	"testing"
)

func TestJsStringCreateAndText(t *testing.T) {
	s := NewJsString("Hello, World!")
	text, ok := s.Text()
	if !ok {
		t.Fatal("Text() returned false")
	}
	if text != "Hello, World!" {
		t.Errorf("Text() = %q", text)
	}
	if s.Len() != 13 {
		t.Errorf("Len() = %d, want 13", s.Len())
	}
}

func TestJsStringConcat(t *testing.T) {
	s1 := NewJsString("Hello, ")
	s2 := NewJsString("World!")
	s3 := s1.Concat(s2)
	text, ok := s3.Text()
	if !ok {
		t.Fatal("Text() returned false")
	}
	if text != "Hello, World!" {
		t.Errorf("Text() = %q", text)
	}
}

func TestJsStringEmpty(t *testing.T) {
	s := NewJsString("")
	if !s.IsEmpty() {
		t.Error("IsEmpty() should be true")
	}
	s2 := NewJsString("x")
	if s2.IsEmpty() {
		t.Error("IsEmpty() should be false")
	}
}

func TestJsStringUnit(t *testing.T) {
	s := NewJsString("ABC")
	u, ok := s.Unit(0)
	if !ok || u != 'A' {
		t.Errorf("Unit(0) = %d, ok=%v", u, ok)
	}
	_, ok = s.Unit(10)
	if ok {
		t.Error("Unit(10) should return false")
	}
}

func TestValueConstructors(t *testing.T) {
	v := Undefined()
	if v.Kind != KindUndefined {
		t.Errorf("Undefined kind = %d", v.Kind)
	}

	v = Null()
	if v.Kind != KindNull {
		t.Errorf("Null kind = %d", v.Kind)
	}

	v = BoolVal(true)
	if v.Kind != KindBool || !v.Bool {
		t.Errorf("BoolVal kind = %d, bool = %v", v.Kind, v.Bool)
	}

	v = NumberVal(42.5)
	if v.Kind != KindNumber || v.Number != 42.5 {
		t.Errorf("NumberVal kind = %d, number = %v", v.Kind, v.Number)
	}

	v = StringVal("test")
	if v.Kind != KindString {
		t.Errorf("StringVal kind = %d", v.Kind)
	}
	text, ok := v.String.Text()
	if !ok || text != "test" {
		t.Errorf("String text = %q, ok = %v", text, ok)
	}

	v = MachineVal()
	if v.Kind != KindMachine {
		t.Errorf("MachineVal kind = %d", v.Kind)
	}
}

func TestValueAsConversions(t *testing.T) {
	v := NumberVal(42)
	n, ok := v.AsNumber()
	if !ok || n != 42 {
		t.Errorf("AsNumber() = %v, ok = %v", n, ok)
	}

	v = BoolVal(true)
	b, ok := v.AsBool()
	if !ok || !b {
		t.Errorf("AsBool() = %v, ok = %v", b, ok)
	}

	v = StringVal("hello")
	s, ok := v.AsString()
	if !ok {
		t.Error("AsString() returned false")
	}
	text, _ := s.Text()
	if text != "hello" {
		t.Errorf("String text = %q", text)
	}
}

func TestValueIsImmutable(t *testing.T) {
	if !Undefined().IsImmutable() {
		t.Error("Undefined should be immutable")
	}
	if !NumberVal(1).IsImmutable() {
		t.Error("Number should be immutable")
	}
	if !StringVal("x").IsImmutable() {
		t.Error("String should be immutable")
	}
	if ArrayVal(nil).IsImmutable() {
		t.Error("Array should not be immutable")
	}
}

func TestValueExpr(t *testing.T) {
	v := Undefined()
	term := v.Expr()
	if term.Kind != TermConst || term.Const.Kind != ConstUndefined {
		t.Errorf("Undefined Expr kind = %d", term.Kind)
	}

	v = NumberVal(42)
	term = v.Expr()
	if term.Kind != TermConst || term.Const.Kind != ConstNumber || term.Const.Number != 42 {
		t.Errorf("Number Expr = %+v", term)
	}

	v = StringVal("hello")
	term = v.Expr()
	if term.Kind != TermConst || term.Const.Kind != ConstString || term.Const.String != "hello" {
		t.Errorf("String Expr = %+v", term)
	}
}

func TestScopeFind(t *testing.T) {
	outer := &Scope{
		Variables: map[string]Value{"x": NumberVal(1)},
	}
	inner := &Scope{
		Variables: map[string]Value{"y": NumberVal(2)},
		Outer:     outer,
	}

	v, ok := inner.Find("y")
	if !ok || v.Number != 2 {
		t.Errorf("Find(y) = %v, ok = %v", v, ok)
	}

	v, ok = inner.Find("x")
	if !ok || v.Number != 1 {
		t.Errorf("Find(x) from inner = %v, ok = %v", v, ok)
	}

	_, ok = inner.Find("z")
	if ok {
		t.Error("Find(z) should return false")
	}
}

func TestScopeAssign(t *testing.T) {
	scope := &Scope{
		Variables: map[string]Value{"x": NumberVal(1)},
	}

	ret := scope.Assign("x", NumberVal(2))
	if ret != nil {
		t.Error("Assign should return nil for existing binding")
	}

	v, ok := scope.Find("x")
	if !ok || v.Number != 2 {
		t.Errorf("Find(x) after assign = %v, ok = %v", v, ok)
	}

	ret = scope.Assign("z", NumberVal(3))
	if ret == nil {
		t.Error("Assign should return value for non-existing binding")
	}
}

func TestMemberOf(t *testing.T) {
	cases := []struct {
		name string
		want Member
	}{
		{"h", MemberMask},
		{"O", MemberMask},
		{"i", MemberPc},
		{"l", MemberKey},
		{"H", MemberValues},
		{"J", MemberTags},
		{"D", MemberPcIndex},
		{"F", MemberKeyIndex},
		{"unknown", MemberUnknown},
	}
	for _, c := range cases {
		if got := MemberOf(c.name); got != c.want {
			t.Errorf("MemberOf(%q) = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestStoredOf(t *testing.T) {
	cases := []struct {
		tag  float64
		want Stored
	}{
		{0, StoredPlain},
		{1, StoredInteger},
		{2, StoredBoolean},
		{3, StoredPlain},
		{5, StoredInteger},
		{6, StoredBoolean},
		{-4, StoredRecord},
		{100, StoredPlain},
	}
	for _, c := range cases {
		if got := StoredOf(c.tag); got != c.want {
			t.Errorf("StoredOf(%v) = %d, want %d", c.tag, got, c.want)
		}
	}
}

func TestRegisterFileReadWrite(t *testing.T) {
	rf := NewRegisterFile()

	rf.Write(0, NumberVal(42), 0)
	v := rf.Read(0)
	n, ok := v.AsNumber()
	if !ok || n != 42 {
		t.Errorf("Read(0) = %v, ok = %v", n, ok)
	}

	rf.Write(1, NumberVal(42), 1)
	v = rf.Read(1)
	n, ok = v.AsNumber()
	if !ok || n != 42 {
		t.Errorf("Read(1) with integer tag = %v, ok = %v", n, ok)
	}

	rf.Write(2, NumberVal(0), 2)
	v = rf.Read(2)
	b, ok := v.AsBool()
	if !ok || !b {
		t.Errorf("Read(2) with boolean tag = %v, ok = %v", b, ok)
	}
}

func TestRegisterFileCopy(t *testing.T) {
	rf := NewRegisterFile()
	rf.Write(0, NumberVal(42), 0)

	rf2 := rf.Copy()
	rf2.Write(0, NumberVal(99), 0)

	v := rf.Read(0)
	n, _ := v.AsNumber()
	if n != 42 {
		t.Errorf("Original changed after copy write: %v", n)
	}

	v = rf2.Read(0)
	n, _ = v.AsNumber()
	if n != 99 {
		t.Errorf("Copy doesn't have new value: %v", n)
	}
}

func TestPosition(t *testing.T) {
	p := NewPosition(42, 7)
	if p.PC != 42 || p.Key != 7 {
		t.Errorf("Position = %+v", p)
	}
}

func TestListing(t *testing.T) {
	l := NewListing(Position{PC: 0, Key: 0})
	if l == nil {
		t.Fatal("NewListing returned nil")
	}
	if len(l.Instructions) != 0 {
		t.Errorf("Empty listing has %d instructions", len(l.Instructions))
	}

	inst := &Instruction{PC: 0, Key: 0, Opcode: 1}
	l.Add(inst)
	if len(l.Instructions) != 1 {
		t.Errorf("Listing has %d instructions after add", len(l.Instructions))
	}

	got := l.Get(Position{PC: 0, Key: 0})
	if got == nil || got.Opcode != 1 {
		t.Errorf("Get returned %+v", got)
	}

	l.AddFailure(Failure{PC: 10, Key: 0})
	if len(l.Failures) != 1 {
		t.Errorf("Listing has %d failures", len(l.Failures))
	}
}
