package deobfuscate

import (
	"testing"
)

func TestInlineAccessors(t *testing.T) {
	source := "T0=function(FB){return FB[5]};\n" +
		"T1=function(FB){return FB._abc123};\n" +
		"var x = T0(obj);\n" +
		"var y = T1(obj);\n"
	result, err := InlineAccessors(source)
	if err != nil {
		t.Fatalf("InlineAccessors: %v", err)
	}
	t.Logf("Result: %s", result)

	if !contains(result, "obj[5]") {
		t.Error("T0(obj) should be inlined to obj[5]")
	}
}

func TestExtractSessionConfig(t *testing.T) {
	source := `
window._cf_chl_opt._abc = "hello";
window._cf_chl_opt._def = 42;
window._cf_chl_opt._ghi = false;
`
	config := ExtractSessionConfig(source)
	if len(config) != 3 {
		t.Fatalf("config count = %d, want 3", len(config))
	}
	if config["_abc"] != "\"hello\"" {
		t.Errorf("_abc = %q", config["_abc"])
	}
	if config["_def"] != "42" {
		t.Errorf("_def = %q", config["_def"])
	}
}

func TestDeobfuscateWithInlining(t *testing.T) {
	source := "var _0x1102f6 = (a=>a).length + 197215877;\n" +
		"T0=function(FB){return FB[5]};\n" +
		"var x = aa(`pnyfQJp3lUCWb40=`);\n" +
		"var y = T0(obj);\n" +
		"obj[197215885^_0x1102f6] = x;\n"
	result, err := DeobfuscateWithInlining(source)
	if err != nil {
		t.Fatalf("DeobfuscateWithInlining: %v", err)
	}
	t.Logf("Result: %s", result)

	if !contains(result, "_cf_chl_opt") {
		t.Error("string not decoded")
	}
	if !contains(result, "obj[5]") {
		t.Error("accessor not inlined")
	}
}
