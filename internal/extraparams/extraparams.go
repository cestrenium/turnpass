// Package extraparams builds the extraParams message that the embedding page
// sends to the iframe's requestExtraParams.
package extraparams

import (
	"encoding/json"
	"time"
)

// Timeline holds loader timestamps from the fingerprint's timeline section.
type Timeline struct {
	ScriptFetch    float64 `json:"script_fetch"`
	ImplicitRender int64   `json:"implicit_render"`
	RenderStart    int64   `json:"render_start"`
	RenderEnd      int64   `json:"render_end"`
	InitStart      int64   `json:"init_start"`
	ParamsStart    int64   `json:"params_start"`
	CollectStart   int64   `json:"collect_start"`
	Sent           int64   `json:"sent"`
}

// ElapsedTimes holds elapsed loader times reported in extraParams.
type ElapsedTimes struct {
	TimeExtraParamsMs int64 `json:"timeExtraParamsMs"`
	TimeInitMs        int64 `json:"timeInitMs"`
	TimeLoadInitMs    int64 `json:"timeLoadInitMs"`
	TimeParamsMs      int64 `json:"timeParamsMs"`
	TimeRenderMs      int64 `json:"timeRenderMs"`
	TimeTiefMs        int64 `json:"timeTiefMs"`
}

// Times returns elapsed times from the timeline.
func (t *Timeline) Times() ElapsedTimes {
	return ElapsedTimes{
		TimeExtraParamsMs: t.Sent - t.RenderStart,
		TimeInitMs:        t.InitStart - t.RenderEnd,
		TimeLoadInitMs:    t.Sent,
		TimeParamsMs:      t.ParamsStart - t.InitStart,
		TimeRenderMs:      t.RenderEnd - t.RenderStart,
		TimeTiefMs:        t.Sent - t.CollectStart,
	}
}

// WidgetParams holds the Turnstile widget configuration.
type WidgetParams struct {
	Sitekey         string `json:"sitekey"`
	Action          string `json:"action,omitempty"`
	CData           string `json:"cData,omitempty"`
	Appearance      string `json:"appearance"`
	Execution       string `json:"execution"`
	ExpiryInterval  int64  `json:"expiry_interval"`
	Language        string `json:"language"`
	RefreshExpired  string `json:"refresh_expired"`
	RefreshTimeout  string `json:"refresh_timeout"`
	Retry           string `json:"retry"`
	RetryInterval   int64  `json:"retry_interval"`
	Theme           string `json:"theme"`
	Size            string `json:"size"`
	FeedbackEnabled bool   `json:"feedback_enabled"`
	ChlPageData     string `json:"chl_page_data,omitempty"`
}

// PageSignals holds the wPr field.
type PageSignals struct {
	Widgets int    `json:"widgets"`
	Mode    string `json:"mode,omitempty"`
}

// StackSample is one entry in the cs array.
type StackSample struct {
	Method  string `json:"method"`
	Elapsed int64  `json:"elapsed"`
	Stack   string `json:"stack"`
	Count   int    `json:"count"`
}

// ExtraParams is the embedding page's reply to requestExtraParams.
type ExtraParams struct {
	Action                      string          `json:"action,omitempty"`
	ApiJsMismatchReloadAttempts int             `json:"apiJsMismatchReloadAttempts"`
	ApiJsMismatchReloadCount    int             `json:"apiJsMismatchReloadCompletedCount"`
	ApiJsResourceTiming         json.RawMessage `json:"apiJsResourceTiming"`
	Appearance                  string          `json:"appearance"`
	LoaderURL                   string          `json:"au"`
	CData                       string          `json:"cData,omitempty"`
	Build                       string          `json:"ch"`
	ChlPageData                 string          `json:"chl_page_data,omitempty"`
	Samples                     []StackSample   `json:"cs"`
	Event                       string          `json:"event"`
	Execution                   string          `json:"execution"`
	ExpiryInterval              int64           `json:"expiry-interval"`
	Language                    string          `json:"language"`
	ChallengeVariant            string          `json:"rcV"`
	RefreshExpired              string          `json:"refresh-expired"`
	RefreshTimeout              string          `json:"refresh-timeout"`
	Retry                       string          `json:"retry"`
	RetryInterval               int64           `json:"retry-interval"`
	Source                      string          `json:"source"`
	Times                       ElapsedTimes    `json:"times"`
	UpgradeAttempts             int             `json:"upgradeAttempts"`
	UpgradeCompletedCount       int             `json:"upgradeCompletedCount"`
	URL                         string          `json:"url"`
	Signals                     PageSignals     `json:"wPr"`
	WidgetID                    string          `json:"widget_id"`
}

// Collect builds the extraParams reply from the page state.
func Collect(pageURL, widgetID, build, loaderURL string, params *WidgetParams, timeline *Timeline, mode string) *ExtraParams {
	times := timeline.Times()
	return &ExtraParams{
		ApiJsMismatchReloadAttempts: 0,
		ApiJsMismatchReloadCount:    0,
		ApiJsResourceTiming:         json.RawMessage(`{}`),
		Appearance:                  defaultStr(params.Appearance, "always"),
		LoaderURL:                   loaderURL,
		Build:                       build,
		Samples:                     []StackSample{{Method: "implicit_render", Elapsed: timeline.ImplicitRender, Stack: "", Count: 1}},
		Event:                       "extraParams",
		Execution:                   defaultStr(params.Execution, "render"),
		ExpiryInterval:              params.ExpiryInterval,
		Language:                    defaultStr(params.Language, "en"),
		ChallengeVariant:            "",
		RefreshExpired:              defaultStr(params.RefreshExpired, "auto"),
		RefreshTimeout:              defaultStr(params.RefreshTimeout, "auto"),
		Retry:                       defaultStr(params.Retry, "auto"),
		RetryInterval:               params.RetryInterval,
		Source:                      "cloudflare-challenge",
		UpgradeAttempts:             0,
		UpgradeCompletedCount:       0,
		URL:                         pageURL,
		Signals:                     PageSignals{Widgets: 1, Mode: mode},
		WidgetID:                    widgetID,
		Times:                       times,
		Action:                      params.Action,
		CData:                       params.CData,
		ChlPageData:                 params.ChlPageData,
	}
}

// Now returns the current time in epoch milliseconds.
func Now() int64 { return time.Now().UnixMilli() }

func defaultStr(val, def string) string {
	if val == "" {
		return def
	}
	return val
}
