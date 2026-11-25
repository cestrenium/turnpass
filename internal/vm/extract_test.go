package vm

import (
	"testing"
)

func TestParseScript(t *testing.T) {
	source := `function foo() { return 42; }`
	script, err := ParseScript(source)
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}
	if script == nil || script.Program == nil {
		t.Fatal("ParseScript returned nil")
	}
}

func TestParseScriptInvalid(t *testing.T) {
	_, err := ParseScript(`function {`)
	if err == nil {
		t.Fatal("expected error for invalid JavaScript")
	}
}

func TestFindVMSimple(t *testing.T) {
	source := `
class VM {
  constructor() {
    this.i = 0;
    this.l = 0;
  }
  run(program) {
    var pc = 0;
    var key = 0;
    while (pc < program.length) {
      var opcode = program[pc] ^ key;
      switch (opcode) {
        case 0:
          pc = pc + 1;
          break;
        case 1:
          pc = pc + 2;
          break;
        default:
          return;
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

	if def.Class == nil {
		t.Error("Class is nil")
	}
	if def.RunFunction == nil {
		t.Error("RunFunction is nil")
	}
	if def.DispatchLoop == nil {
		t.Error("DispatchLoop is nil")
	}
	if def.Constructor == nil {
		t.Error("Constructor is nil")
	}
	t.Logf("Found: %s", def.String())
}

func TestFindVMInIIFE(t *testing.T) {
	source := `
(function() {
  class VM {
    constructor() { this.x = 0; }
    run(p) {
      while (true) {
        switch (p[0]) {
          case 0: break;
          default: return;
        }
      }
    }
  }
  function helper() { return 1; }
})();
`
	script, err := ParseScript(source)
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}

	def, err := FindVM(script)
	if err != nil {
		t.Fatalf("FindVM: %v", err)
	}

	if def.Class == nil {
		t.Error("Class is nil")
	}
	if len(def.Functions) < 1 {
		t.Errorf("Expected at least 1 function, got %d", len(def.Functions))
	}
}

func TestFindVMNoClass(t *testing.T) {
	source := `var x = 1;`
	script, err := ParseScript(source)
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}

	_, err = FindVM(script)
	if err == nil {
		t.Fatal("expected error for script with no VM class")
	}
}
