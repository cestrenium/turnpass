package payload

import (
	"encoding/json"
	"testing"

	"github.com/cestrenium/turnpass/internal/answers"
	"github.com/cestrenium/turnpass/internal/extraparams"
)

func TestPayloadSetGet(t *testing.T) {
	p := &Payload{}
	p.Set("a", 1)
	p.Set("b", "hello")
	p.Set("a", 2) // overwrite

	if p.Len() != 2 {
		t.Errorf("Len = %d, want 2", p.Len())
	}

	v, ok := p.Get("a")
	if !ok || v != 2 {
		t.Errorf("Get(a) = %v, ok = %v", v, ok)
	}

	_, ok = p.Get("nonexistent")
	if ok {
		t.Error("Get should return false for missing key")
	}
}

func TestPayloadMarshalJSON(t *testing.T) {
	p := &Payload{}
	p.Set("key", "value")
	p.Set("num", 42)

	data, err := p.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if m["key"] != "value" {
		t.Errorf("key = %v", m["key"])
	}
	if m["num"] != float64(42) {
		t.Errorf("num = %v", m["num"])
	}
}

func TestBuildFirstPayload(t *testing.T) {
	ans := &answers.Answers{
		Reference: "abcdef0123456789",
		Navigator: answers.Navigator{
			Platform:            "iPhone",
			Languages:           []string{"en-US"},
			HardwareConcurrency: 4,
			UserAgent:           "TestUA",
		},
		Probes: map[string]answers.Probe{
			"2": {Duration: 73, Fields: map[string]json.RawMessage{"f": json.RawMessage(`1`)}},
		},
		Globals: map[string]json.RawMessage{"g": json.RawMessage(`1`)},
	}

	ep := &extraparams.ExtraParams{
		Action:   "login",
		CData:    "session42",
		WidgetID: "abc12",
		Language: "en",
	}

	options := map[string]interface{}{
		"cf_chl": "token123",
		"ray":    "ray-id",
	}

	p, err := BuildFirstPayload(ans, ep, options)
	if err != nil {
		t.Fatalf("BuildFirstPayload: %v", err)
	}

	if v, ok := p.Get("hardwareConcurrency"); !ok || v != 4 {
		t.Errorf("hardwareConcurrency = %v, ok = %v", v, ok)
	}
	if v, ok := p.Get("userAgent"); !ok || v != "TestUA" {
		t.Errorf("userAgent = %v, ok = %v", v, ok)
	}
	if v, ok := p.Get("reference"); !ok || v != "abcdef0123456789" {
		t.Errorf("reference = %v, ok = %v", v, ok)
	}
	if v, ok := p.Get("action"); !ok || v != "login" {
		t.Errorf("action = %v, ok = %v", v, ok)
	}
	if v, ok := p.Get("cf_chl"); !ok || v != "token123" {
		t.Errorf("cf_chl = %v, ok = %v", v, ok)
	}
	if v, ok := p.Get("globalsCount"); !ok || v != 1 {
		t.Errorf("globalsCount = %v, ok = %v", v, ok)
	}

	// Check probes summary.
	probesVal, ok := p.Get("probes")
	if !ok {
		t.Fatal("probes not found")
	}
	probes, ok := probesVal.(map[string]interface{})
	if !ok {
		t.Fatal("probes is not a map")
	}
	if _, ok := probes["2"]; !ok {
		t.Error("probe 2 not in summary")
	}
}

func TestBuildProbePayload(t *testing.T) {
	ans := &answers.Answers{
		Reference: "abcdef0123456789",
		Navigator: answers.Navigator{HardwareConcurrency: 4, UserAgent: "TestUA"},
		Probes: map[string]answers.Probe{
			"2": {Duration: 73, Fields: map[string]json.RawMessage{"f": json.RawMessage(`1`)}},
			"3": {Duration: 12, Fields: map[string]json.RawMessage{"g": json.RawMessage(`2`)}},
		},
		Globals: map[string]json.RawMessage{"g": json.RawMessage(`1`)},
	}

	first := &Payload{}
	first.Set("reference", "abcdef0123456789")

	p, err := BuildProbePayload(ans, first)
	if err != nil {
		t.Fatalf("BuildProbePayload: %v", err)
	}

	if _, ok := p.Get("probe_2"); !ok {
		t.Error("probe_2 not in payload")
	}
	if _, ok := p.Get("probe_3"); !ok {
		t.Error("probe_3 not in payload")
	}
	if _, ok := p.Get("globals"); !ok {
		t.Error("globals not in payload")
	}
}

func TestAppendSendTime(t *testing.T) {
	p := &Payload{}
	p.Set("x", 1)

	AppendSendTime(p, 1234567890, []interface{}{"resource1"})

	if v, ok := p.Get("sentMs"); !ok || v != int64(1234567890) {
		t.Errorf("sentMs = %v, ok = %v", v, ok)
	}
	if v, ok := p.Get("resources"); !ok {
		t.Errorf("resources not found")
	} else {
		resources, ok := v.([]interface{})
		if !ok || len(resources) != 1 {
			t.Errorf("resources = %v", v)
		}
	}
}

func TestBuildFirstPayloadNilAnswers(t *testing.T) {
	_, err := BuildFirstPayload(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil answers")
	}
}
