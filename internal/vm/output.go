package vm

type Position struct {
	PC  uint32
	Key uint8
}

func NewPosition(pc uint32, key uint8) Position { return Position{PC: pc, Key: key} }

type Instruction struct {
	PC     uint32
	Key    uint8
	Opcode uint8
	Paths  []Path
}

type Path struct {
	Exit       Exit
	Effects    []Effect
	Successors []Position
	Known      []RegisterValue
}

type Exit struct {
	Kind    ExitKind
	Target  Position
	Closure Term
	Return  Term
	Thrown  Term
}

type ExitKind int

const (
	ExitJump ExitKind = iota
	ExitCall
	ExitReturn
	ExitThrow
	ExitFallthrough
	ExitUnfollowed
)

type Effect struct {
	Kind     EffectKind
	Register uint8
	Value    Term
	Field    string
	Cell     uint32
}

type EffectKind int

const (
	EffectWriteRegister EffectKind = iota
	EffectWriteField
	EffectWriteCell
	EffectDeleteField
	EffectPushArray
	EffectPopArray
)

type RegisterValue struct {
	Register uint8
	Value    Value
}

type Failure struct {
	PC    uint32
	Key   uint8
	Cause Cause
}

type Cause struct {
	Kind    CauseKind
	Opcode  uint8
	Reason  string
	Reasons []string
	Limit   int
}

type CauseKind int

const (
	CausePastEnd CauseKind = iota
	CauseNoHandler
	CauseUndecoded
	CauseFaults
	CauseTooManyPaths
)

type Listing struct {
	Instructions map[Position]*Instruction
	Failures     []Failure
	Entry        Position
}

func NewListing(entry Position) *Listing {
	return &Listing{
		Instructions: make(map[Position]*Instruction),
		Entry:        entry,
	}
}

func (l *Listing) Add(inst *Instruction) {
	pos := Position{PC: inst.PC, Key: inst.Key}
	l.Instructions[pos] = inst
}

func (l *Listing) AddFailure(f Failure) {
	l.Failures = append(l.Failures, f)
}

func (l *Listing) Get(pos Position) *Instruction {
	return l.Instructions[pos]
}

type ProgramOutcome struct {
	Kind  ProgramOutcomeKind
	Token string
}

type ProgramOutcomeKind int

const (
	ProgramComplete ProgramOutcomeKind = iota
	ProgramInteraction
	ProgramOther
)

func ProgramOutcomeOf(l *Listing) ProgramOutcome {
	if l == nil {
		return ProgramOutcome{Kind: ProgramOther}
	}
	for _, inst := range l.Instructions {
		for _, path := range inst.Paths {
			if path.Exit.Kind == ExitReturn {
				if path.Exit.Return.Kind == TermConst && path.Exit.Return.Const.Kind == ConstString {
					return ProgramOutcome{Kind: ProgramComplete, Token: path.Exit.Return.Const.String}
				}
			}
		}
	}
	return ProgramOutcome{Kind: ProgramOther}
}
