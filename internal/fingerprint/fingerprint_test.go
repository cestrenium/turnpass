package fingerprint

import (
	"encoding/json"
	"testing"
)

const safariExcerpt = `{
  "engine": "webkit",
  "transport": {
    "profile": "safari_ios_26.2",
    "platform": "ios",
    "headers": {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)"},
    "requests": {
      "headers": {
        "navigation": ["sec-fetch-dest: document", "user-agent"],
        "iframe": ["sec-fetch-dest: iframe", "user-agent", "referer"]
      }
    }
  },
  "timeline": {"sent": 500},
  "intervals": {"send": 49},
  "orchestrator": {"callback_ms": 30},
  "resource_timing": {"sizes_exposed": false},
  "interaction": {"ready_delay_ms": 1000},
  "second": {"startup_ms": 281}
}`

func TestParseValid(t *testing.T) {
	fp, err := Parse([]byte(safariExcerpt))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if fp.Engine != EngineWebKit {
		t.Errorf("Engine = %q", fp.Engine)
	}
	if fp.Transport.Profile != "safari_ios_26.2" {
		t.Errorf("Profile = %q", fp.Transport.Profile)
	}
	if fp.UserAgent() != "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)" {
		t.Errorf("UserAgent = %q", fp.UserAgent())
	}
	order := fp.HeaderOrder("iframe")
	if len(order) != 3 || order[1] != "user-agent" {
		t.Errorf("HeaderOrder(iframe) = %v", order)
	}
}

func TestParseUnknownKeysIgnored(t *testing.T) {
	data := `{"engine":"chromium","transport":{"profile":"chrome","platform":"desktop","requests":{"headers":{"navigation":["user-agent"]}},"unknown_key":42},"timeline":{},"intervals":{},"orchestrator":{},"resource_timing":{},"interaction":{},"second":{},"unknown_top":true}`
	fp, err := Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if fp.Engine != EngineChromium {
		t.Errorf("Engine = %q", fp.Engine)
	}
}

func TestValidateReportsMissingFields(t *testing.T) {
	cases := []struct {
		name   string
		patch  string
		expect string
	}{
		{"missing engine", `{}`, "missing field `engine`"},
		{"bad engine", `{"engine":"gecko","transport":{"profile":"x","platform":"y","requests":{"headers":{"n":["user-agent"]}}},"timeline":{},"intervals":{},"orchestrator":{},"resource_timing":{},"interaction":{},"second":{}}`, "unknown variant"},
		{"missing transport.profile", `{"engine":"chromium","transport":{"platform":"y","requests":{"headers":{"n":["user-agent"]}}},"timeline":{},"intervals":{},"orchestrator":{},"resource_timing":{},"interaction":{},"second":{}}`, "missing field `transport.profile`"},
		{"missing requests.headers", `{"engine":"chromium","transport":{"profile":"x","platform":"y"},"timeline":{},"intervals":{},"orchestrator":{},"resource_timing":{},"interaction":{},"second":{}}`, "missing field `transport.requests.headers`"},
		{"missing user-agent", `{"engine":"chromium","transport":{"profile":"x","platform":"y","requests":{"headers":{"navigation":["accept"]}}},"timeline":{},"intervals":{},"orchestrator":{},"resource_timing":{},"interaction":{},"second":{}}`, "no `user-agent`"},
		{"missing timeline", `{"engine":"chromium","transport":{"profile":"x","platform":"y","requests":{"headers":{"n":["user-agent"]}}},"intervals":{},"orchestrator":{},"resource_timing":{},"interaction":{},"second":{}}`, "missing field `timeline`"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.patch))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.expect)
			}
			if !contains(err.Error(), c.expect) {
				t.Errorf("error = %q, want substring %q", err.Error(), c.expect)
			}
		})
	}
}

func TestLoadAnswersEmpty(t *testing.T) {
	fp := &Fingerprint{}
	raw, err := fp.LoadAnswers("/tmp/nonexistent.json")
	if err != nil {
		t.Fatalf("LoadAnswers: %v", err)
	}
	if raw != nil {
		t.Errorf("LoadAnswers = %v, want nil", raw)
	}
}

func TestParseFloat(t *testing.T) {
	var v map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{"a":1.5,"b":2}`), &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if string(v["a"]) != "1.5" {
		t.Errorf("a = %s", v["a"])
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
