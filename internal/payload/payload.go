// Package payload constructs challenge payloads from recorded answers and
// session state.
package payload

import (
	"encoding/json"
	"fmt"

	"github.com/cestrenium/turnpass/internal/answers"
	"github.com/cestrenium/turnpass/internal/extraparams"
)

// PayloadField is one key-value pair in a payload.
type PayloadField struct {
	Key   string
	Value interface{}
}

// Payload is a key-ordered map of payload field names to their values.
type Payload struct {
	Fields []PayloadField
}

func (p *Payload) Set(key string, value interface{}) {
	for i, f := range p.Fields {
		if f.Key == key {
			p.Fields[i].Value = value
			return
		}
	}
	p.Fields = append(p.Fields, PayloadField{Key: key, Value: value})
}

func (p *Payload) Get(key string) (interface{}, bool) {
	for _, f := range p.Fields {
		if f.Key == key {
			return f.Value, true
		}
	}
	return nil, false
}

func (p *Payload) Len() int { return len(p.Fields) }

func (p *Payload) MarshalJSON() ([]byte, error) {
	if len(p.Fields) == 0 {
		return []byte("{}"), nil
	}
	m := make(map[string]interface{}, len(p.Fields))
	for _, f := range p.Fields {
		m[f.Key] = f.Value
	}
	return json.Marshal(m)
}

// BuildFirstPayload constructs the initial payload from the session state,
// recorded answers, and extraParams.
func BuildFirstPayload(
	ans *answers.Answers,
	ep *extraparams.ExtraParams,
	options map[string]interface{},
) (*Payload, error) {
	if ans == nil {
		return nil, fmt.Errorf("answers are required for payload construction")
	}

	p := &Payload{}

	for k, v := range options {
		p.Set(k, v)
	}

	p.Set("hardwareConcurrency", ans.Navigator.HardwareConcurrency)
	p.Set("userAgent", ans.Navigator.UserAgent)
	p.Set("platform", ans.Navigator.Platform)
	p.Set("languages", ans.Navigator.Languages)

	if ep != nil {
		p.Set("action", ep.Action)
		p.Set("cData", ep.CData)
		p.Set("widgetId", ep.WidgetID)
		p.Set("language", ep.Language)
	}

	p.Set("reference", ans.Reference)

	probeSummary := make(map[string]interface{})
	for index, probe := range ans.Probes {
		probeSummary[index] = map[string]interface{}{
			"duration": probe.Duration,
			"fields":   len(probe.Fields),
		}
	}
	p.Set("probes", probeSummary)
	p.Set("globalsCount", len(ans.Globals))

	return p, nil
}

// BuildProbePayload extends the first payload with actual probe answer data.
func BuildProbePayload(
	ans *answers.Answers,
	first *Payload,
) (*Payload, error) {
	if ans == nil {
		return nil, fmt.Errorf("answers are required for probe payload")
	}

	p := &Payload{}
	for _, f := range first.Fields {
		p.Set(f.Key, f.Value)
	}

	for index, probe := range ans.Probes {
		key := fmt.Sprintf("probe_%s", index)
		fieldData := make(map[string]json.RawMessage)
		for fname, fval := range probe.Fields {
			fieldData[fname] = fval
		}
		p.Set(key, fieldData)
	}

	if len(ans.Globals) > 0 {
		p.Set("globals", ans.Globals)
	}

	if len(ans.Stylesheets) > 0 {
		p.Set("stylesheets", ans.Stylesheets)
	}

	return p, nil
}

// AppendSendTime adds the send timestamp and resource timing to the payload.
func AppendSendTime(p *Payload, sentMs int64, resources []interface{}) {
	p.Set("sentMs", sentMs)
	if len(resources) > 0 {
		p.Set("resources", resources)
	}
}
