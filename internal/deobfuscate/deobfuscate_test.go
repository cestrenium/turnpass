package deobfuscate

import (
	"os"
	"testing"
)

func TestResolveXORKeys(t *testing.T) {
	source := `
var _0x1102f6 = (a=>a).length + 197215877;
var _0x59c0b1 = (a=>a).length + 772744210;
`
	d := New(source)
	d.resolveXORKeys()

	if v, ok := d.XORKeys["_0x1102f6"]; !ok || v != 197215878 {
		t.Errorf("_0x1102f6 = %v, want 197215878", v)
	}
	if v, ok := d.XORKeys["_0x59c0b1"]; !ok || v != 772744211 {
		t.Errorf("_0x59c0b1 = %v, want 772744211", v)
	}
}

func TestFoldXORChains(t *testing.T) {
	d := New("")
	// evalXORChain only works on chains of pure numbers separated by ^.
	// Parenthesized sub-expressions are not handled by the text-level folder.
	cases := []struct {
		input string
		want  int64
	}{
		{"10299^46025", 10299 ^ 46025},
		{"1^2^3^4^5", 1 ^ 2 ^ 3 ^ 4 ^ 5},
		{"100^200^300", 100 ^ 200 ^ 300},
	}
	for _, c := range cases {
		got := d.evalXORChain(c.input)
		if got != c.want {
			t.Errorf("evalXORChain(%q) = %d, want %d", c.input, got, c.want)
		}
	}
}

func TestFoldConstants(t *testing.T) {
	d := New("")
	source := "var x = 100^200^300; var y = (42|0);"
	result := d.foldConstants(source)
	expected := int64(100 ^ 200 ^ 300)
	if !contains(result, "var x = "+itoa(expected)) {
		t.Errorf("foldConstants: expected %d in result, got: %s", expected, result)
	}
	if !contains(result, "var y = 42") {
		t.Errorf("foldConstants: (42|0) should become 42, got: %s", result)
	}
}

func TestReplaceXORAccesses(t *testing.T) {
	d := New("")
	d.XORKeys["_0x1102f6"] = 197215878
	source := "x[197215885^_0x1102f6] = 1; y = _0x1102f6^197215876;"
	result := d.replaceXORAccesses(source)
	// 197215885 ^ 197215878 = 11
	if !contains(result, "x[11]") {
		t.Errorf("expected x[7] in result: %s", result)
	}
	if !contains(result, "y = 2") {
		t.Errorf("expected y = 2 in result: %s", result)
	}
}

func TestDecodeAaString(t *testing.T) {
	cases := []struct {
		encoded string
		want    string
	}{
		{"mlatdpR6qg==", "cITimeS"},
		{"pnyfQJp3lUCWb40=", "_cf_chl_opt"},
		{"pi+BL50nynrP", "_0x0d83e6"},
		{"nX6LdJRwnXo=", "darkmode"},
	}
	for _, c := range cases {
		got := DecodeAaString(c.encoded)
		if got != c.want {
			t.Errorf("DecodeAaString(%q) = %q, want %q", c.encoded, got, c.want)
		}
	}
}

func TestFindStringDecoder(t *testing.T) {
	cases := []struct {
		source string
		want   string
	}{
		{"var x = aa(`test`);", "aa"},
		{"var x = a0(`test`);", "a0"},
		{"var x = noDecoder('test');", ""},
	}
	for _, c := range cases {
		d := New(c.source)
		d.findStringDecoder(c.source)
		if d.StringDecoderName != c.want {
			t.Errorf("findStringDecoder: got %q, want %q", d.StringDecoderName, c.want)
		}
	}
}

func TestDecodeStringCalls(t *testing.T) {
	d := New("")
	d.StringDecoderName = "aa"
	source := "var x = aa(`pnyfQJp3lUCWb40=`); var y = aa(`nX6LdJRwnXo=`);"
	result := d.decodeStringCalls(source)
	if !contains(result, "`_cf_chl_opt`") {
		t.Errorf("expected _cf_chl_opt in result: %s", result)
	}
	if !contains(result, "`darkmode`") {
		t.Errorf("expected darkmode in result: %s", result)
	}
}

func TestDeobfuscateFull(t *testing.T) {
	source := "var _0x1102f6 = (a=>a).length + 197215877;\n" +
		"var x = aa(`pnyfQJp3lUCWb40=`);\n" +
		"var y = 10299^(46025^221581)^57172;\n" +
		"var z = (42|0);\n" +
		"obj[197215885^_0x1102f6] = x;\n"
	d := New(source)
	result, err := d.Deobfuscate()
	if err != nil {
		t.Fatalf("Deobfuscate: %v", err)
	}
	t.Logf("Stats: %s", d.Stats())
	t.Logf("Result: %s", result)

	if !contains(result, "_cf_chl_opt") {
		t.Error("string not decoded in result")
	}
}

func TestDeobfuscateRealOrchestrator(t *testing.T) {
	path := "/tmp/turnpass-debug/orchestrator.js"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("orchestrator not available at %s", path)
	}

	d := New(string(data))
	result, err := d.Deobfuscate()
	if err != nil {
		t.Fatalf("Deobfuscate: %v", err)
	}

	t.Logf("Stats: %s", d.Stats())
	t.Logf("Original size: %d, Deobfuscated size: %d", len(data), len(result))

	if len(d.XORKeys) == 0 {
		t.Error("no XOR keys found")
	}
	if len(d.StringCache) == 0 {
		t.Error("no strings decoded")
	}

	// Verify some known decoded strings are in the result.
	if !contains(result, "_cf_chl_opt") {
		t.Error("_cf_chl_opt not found in deobfuscated result")
	}
	if !contains(result, "BigInt") {
		t.Error("BigInt not found in deobfuscated result")
	}
}

// Helpers

func contains(s, sub string) bool {
	return len(s) >= len(sub) && strings_Contains(s, sub)
}

func strings_Contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
