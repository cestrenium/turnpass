package handlers

import (
	"context"
	"strings"
	"testing"

	"github.com/cestrenium/turnpass/api/sessions"
	"github.com/cestrenium/turnpass/api/types"
	"github.com/cestrenium/turnpass/internal/browserprofile"
	"github.com/cestrenium/turnpass/internal/solver"
)

func newDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	b, err := browserprofile.FromJSON([]byte(`{
  "engine": "chromium",
  "transport": {"profile": "chrome", "platform": "desktop", "headers": {"User-Agent": "X/1"}, "requests": {"headers": {"navigation": ["user-agent"]}}},
  "timeline": {}, "intervals": {}, "orchestrator": {}, "resource_timing": {}, "interaction": {}, "second": {}
}`), nil, nil)
	if err != nil {
		t.Fatalf("FromJSON: %v", err)
	}
	return NewDispatcher(sessions.New(0), solver.New(b), "test", 0)
}

func TestUnknownCmd(t *testing.T) {
	d := newDispatcher(t)
	resp := d.Handle(context.Background(), types.Request{Cmd: "wat"})
	if resp.Status != types.StatusError {
		t.Errorf("Status = %q", resp.Status)
	}
	if !strings.Contains(resp.Message, "Unknown cmd") {
		t.Errorf("Message = %q", resp.Message)
	}
	if resp.StartTimestamp == 0 || resp.EndTimestamp == 0 {
		t.Error("timestamps not set")
	}
	if resp.Version != "test" {
		t.Errorf("Version = %q", resp.Version)
	}
}

func TestSessionCreateListDestroy(t *testing.T) {
	d := newDispatcher(t)
	r1 := d.Handle(context.Background(), types.Request{Cmd: "sessions.create", Session: "a"})
	if r1.Status != types.StatusOK {
		t.Fatalf("create: %+v", r1)
	}
	r2 := d.Handle(context.Background(), types.Request{Cmd: "sessions.list"})
	if r2.Status != types.StatusOK {
		t.Fatalf("list: %+v", r2)
	}
	if !strings.Contains(r2.Solution.HTML, "\"a\"") {
		t.Errorf("list HTML = %q", r2.Solution.HTML)
	}
	r3 := d.Handle(context.Background(), types.Request{Cmd: "sessions.destroy", Session: "a"})
	if r3.Status != types.StatusOK {
		t.Fatalf("destroy: %+v", r3)
	}
}

func TestSessionDestroyMissing(t *testing.T) {
	d := newDispatcher(t)
	r := d.Handle(context.Background(), types.Request{Cmd: "sessions.destroy", Session: "nope"})
	if r.Status != types.StatusError {
		t.Errorf("Status = %q", r.Status)
	}
}

func TestRequestGetRequiresURL(t *testing.T) {
	d := newDispatcher(t)
	r := d.Handle(context.Background(), types.Request{Cmd: "request.get"})
	if r.Status != types.StatusError {
		t.Errorf("Status = %q", r.Status)
	}
}

func TestResolveProxyURL(t *testing.T) {
	cases := []struct {
		in   map[string]string
		want string
	}{
		{nil, ""},
		{map[string]string{}, ""},
		{map[string]string{"server": "http://p:8080"}, "http://p:8080"},
		{map[string]string{"server": "http://p:8080", "user": "u", "pass": "pw"}, "http://u:pw@p:8080"},
	}
	for _, c := range cases {
		if got := ResolveProxyURL(c.in); got != c.want {
			t.Errorf("ResolveProxyURL(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
