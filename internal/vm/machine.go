package vm

import (
	"fmt"

	"github.com/dop251/goja/ast"
)

// Machine is one session's VM, ready to decode instructions.
type Machine struct {
	Session *Session
}

func NewMachine(session *Session) *Machine {
	return &Machine{Session: session}
}

func NewMachineFromDefinition(def *VMDefinition) (*Machine, error) {
	session, err := NewSession(def)
	if err != nil {
		return nil, err
	}
	return NewMachine(session), nil
}

// Disassemble decodes a VM program and produces a Listing of all reachable instructions.
func (m *Machine) Disassemble(program []byte) (*Listing, error) {
	if m.Session == nil {
		return nil, fmt.Errorf("no session")
	}
	listing := NewListing(m.Session.Entry)
	type workItem struct {
		pc  uint32
		key uint8
	}
	visited := make(map[Position]bool)
	var worklist []workItem
	worklist = append(worklist, workItem{pc: m.Session.Entry.PC, key: m.Session.Entry.Key})
	maxInstructions := 100000
	instructionCount := 0
	for len(worklist) > 0 && instructionCount < maxInstructions {
		item := worklist[0]
		worklist = worklist[1:]
		pos := Position{PC: item.pc, Key: item.key}
		if visited[pos] {
			continue
		}
		visited[pos] = true
		decoded, err := m.Session.EvaluateDispatchLoop(program, item.pc, item.key)
		if err != nil {
			listing.AddFailure(Failure{PC: item.pc, Key: item.key, Cause: Cause{Kind: CauseUndecoded, Reason: err.Error()}})
			continue
		}
		handler, ok := m.Session.Handlers[decoded.Opcode]
		if !ok {
			listing.AddFailure(Failure{PC: item.pc, Key: item.key, Cause: Cause{Kind: CauseNoHandler, Opcode: decoded.Opcode}})
			continue
		}
		paths := m.executeHandler(handler, program, item.pc+1, decoded.Key)
		inst := &Instruction{PC: item.pc, Key: item.key, Opcode: decoded.Opcode, Paths: paths}
		listing.Add(inst)
		instructionCount++
		for _, path := range paths {
			for _, succ := range path.Successors {
				succPos := Position{PC: succ.PC, Key: succ.Key}
				if !visited[succPos] {
					worklist = append(worklist, workItem{pc: succ.PC, key: succ.Key})
				}
			}
		}
	}
	return listing, nil
}

func (m *Machine) executeHandler(handler *ast.FunctionLiteral, program []byte, pc uint32, key uint8) []Path {
	if handler == nil || handler.Body == nil {
		return []Path{{Exit: Exit{Kind: ExitUnfollowed}}}
	}
	explorer := NewPathExplorer(m.Session, program)
	return explorer.ExploreHandler(handler, pc, key)
}

func (ev *Evaluator) ExecuteHandlerBody(fn *ast.FunctionLiteral) (FlowKind, Value, error) {
	if fn.Body == nil {
		return FlowNormal, Undefined(), nil
	}
	if fn.ParameterList != nil {
		for i, param := range fn.ParameterList.List {
			if i == 0 {
				name := paramName(param)
				if name != "" {
					ev.Scope.Variables[name] = MachineVal()
				}
			}
		}
	}
	var result Value = Undefined()
	for _, stmt := range fn.Body.List {
		flow, val, err := ev.ExecuteStatement(stmt)
		if err != nil {
			return FlowThrow, Undefined(), err
		}
		if flow == FlowReturn {
			return FlowReturn, val, nil
		}
		if flow == FlowThrow {
			return FlowThrow, val, nil
		}
		if flow == FlowBreak {
			return FlowBreak, result, nil
		}
	}
	return FlowNormal, result, nil
}

func (m *Machine) Instruction(program []byte, pc uint32, key uint8) (*Instruction, error) {
	decoded, err := m.Session.EvaluateDispatchLoop(program, pc, key)
	if err != nil {
		return nil, err
	}
	handler, ok := m.Session.Handlers[decoded.Opcode]
	if !ok {
		return nil, fmt.Errorf("no handler for opcode %d", decoded.Opcode)
	}
	paths := m.executeHandler(handler, program, pc+1, decoded.Key)
	return &Instruction{PC: pc, Key: key, Opcode: decoded.Opcode, Paths: paths}, nil
}
