package extraparams

import (
	"encoding/json"
	"testing"
)

func TestTimelineTimes(t *testing.T) {
	tl := &Timeline{
		ScriptFetch:    90.0,
		ImplicitRender: 1,
		RenderStart:    1,
		RenderEnd:      3,
		InitStart:      498,
		ParamsStart:    498,
		CollectStart:   498,
		Sent:           500,
	}
	times := tl.Times()
	if times.TimeExtraParamsMs != 499 {
		t.Errorf("TimeExtraParamsMs = %d, want 499", times.TimeExtraParamsMs)
	}
	if times.TimeInitMs != 495 {
		t.Errorf("TimeInitMs = %d, want 495", times.TimeInitMs)
	}
	if times.TimeLoadInitMs != 500 {
		t.Errorf("TimeLoadInitMs = %d, want 500", times.TimeLoadInitMs)
	}
}

func TestCollect(t *testing.T) {
	tl := &Timeline{
		ScriptFetch:    90.0,
		ImplicitRender: 1,
		RenderStart:    1,
		RenderEnd:      3,
		InitStart:      498,
		ParamsStart:    498,
		CollectStart:   498,
		Sent:           500,
	}
	params := &WidgetParams{
		Sitekey:  "0xTEST",
		Theme:    "auto",
		Size:     "normal",
		Language: "en",
	}
	ep := Collect("https://example.com/", "abc12", "e694063b5082",
		"https://challenges.cloudflare.com/turnstile/v0/api.js", params, tl, "managed")

	if ep.URL != "https://example.com/" {
		t.Errorf("URL = %q", ep.URL)
	}
	if ep.WidgetID != "abc12" {
		t.Errorf("WidgetID = %q", ep.WidgetID)
	}
	if ep.Build != "e694063b5082" {
		t.Errorf("Build = %q", ep.Build)
	}
	if ep.LoaderURL != "https://challenges.cloudflare.com/turnstile/v0/api.js" {
		t.Errorf("LoaderURL = %q", ep.LoaderURL)
	}
	if ep.Event != "extraParams" {
		t.Errorf("Event = %q", ep.Event)
	}
	if ep.Source != "cloudflare-challenge" {
		t.Errorf("Source = %q", ep.Source)
	}
	if ep.Signals.Mode != "managed" {
		t.Errorf("Mode = %q", ep.Signals.Mode)
	}
	if len(ep.Samples) != 1 {
		t.Errorf("Samples count = %d", len(ep.Samples))
	}
}

func TestMarshalJSON(t *testing.T) {
	tl := &Timeline{
		ScriptFetch: 90.0, ImplicitRender: 1, RenderStart: 1, RenderEnd: 3,
		InitStart: 498, ParamsStart: 498, CollectStart: 498, Sent: 500,
	}
	params := &WidgetParams{Sitekey: "0xTEST", Theme: "auto", Size: "normal", Language: "en"}
	ep := Collect("https://example.com/", "abc12", "e694063b5082",
		"https://challenges.cloudflare.com/turnstile/v0/api.js", params, tl, "managed")

	data, err := json.Marshal(ep)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Verify it's valid JSON and has expected fields.
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	required := []string{"au", "ch", "cs", "event", "source", "url", "wPr", "widget_id", "times"}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("missing field %q in JSON output", key)
		}
	}
}
