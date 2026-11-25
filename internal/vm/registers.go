package vm

// Member identifies the meaning of a field on the register file.
type Member int

const (
	MemberUnknown Member = iota
	MemberMask
	MemberInteger
	MemberPc
	MemberKey
	MemberOtherPc
	MemberOtherKey
	MemberPcIndex
	MemberKeyIndex
	MemberValues
	MemberTags
	MemberProgram
	MemberRegisters
)

func MemberOf(name string) Member {
	switch name {
	case "h", "O", "K", "L":
		return MemberMask
	case "j", "m":
		return MemberInteger
	case "i":
		return MemberPc
	case "l":
		return MemberKey
	case "A":
		return MemberOtherPc
	case "v":
		return MemberOtherKey
	case "D":
		return MemberPcIndex
	case "F":
		return MemberKeyIndex
	case "H":
		return MemberValues
	case "J":
		return MemberTags
	default:
		return MemberUnknown
	}
}

type Stored int

const (
	StoredPlain Stored = iota
	StoredInteger
	StoredBoolean
	StoredRecord
)

func StoredOf(tag float64) Stored {
	t := int32(tag)
	if t == -4 {
		return StoredRecord
	}
	switch t & 3 {
	case 1:
		return StoredInteger
	case 2:
		return StoredBoolean
	default:
		return StoredPlain
	}
}

func StoredIntegerShift(tag float64) int32 { return int32(tag) >> 2 }
func StoredBooleanShift(tag float64) int32 { return int32(tag) >> 2 }

type Layout struct {
	PC      uint8
	Key     uint8
	Program uint8
	Cells   uint8
}

type RegisterFile struct {
	Values      [256]Value
	Tags        [256]float64
	Mask        float64
	Digest      float64
	IntegerFlag bool
	PC          uint32
	Key         uint8
	OtherPC     Value
	OtherKey    Value
}

func NewRegisterFile() *RegisterFile { return &RegisterFile{} }

func (r *RegisterFile) Read(index uint8) Value {
	tag := r.Tags[index]
	value := r.Values[index]
	switch StoredOf(tag) {
	case StoredInteger:
		if n, ok := value.AsNumber(); ok {
			return NumberVal(float64(int32(n) ^ StoredIntegerShift(tag)))
		}
	case StoredBoolean:
		if n, ok := value.AsNumber(); ok {
			return BoolVal(int32(n) == StoredBooleanShift(tag))
		}
	case StoredRecord:
		return value
	case StoredPlain:
		return value
	}
	return value
}

func (r *RegisterFile) Write(index uint8, value Value, tag float64) {
	r.Values[index] = value
	r.Tags[index] = tag
}

func (r *RegisterFile) WriteValue(index uint8, value Value) {
	r.Values[index] = value
}

func (r *RegisterFile) WriteTag(index uint8, tag float64) {
	r.Tags[index] = tag
}

func (r *RegisterFile) Copy() *RegisterFile {
	c := *r
	return &c
}
