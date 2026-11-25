package types

import (
	"encoding/json"
	"testing"
)

func TestRequestRoundtrip(t *testing.T) {
	req := Request{
		Cmd:        "request.get",
		URL:        "https://example.com/",
		MaxTimeout: 60000,
		Session:    "s1",
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Request
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Cmd != "request.get" || got.URL != "https://example.com/" || got.Session != "s1" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}

func TestNewOK(t *testing.T) {
	r := NewOK("done", "1.0.0", "s1", &Solution{URL: "https://example.com/", Status: 200})
	if r.Status != StatusOK {
		t.Errorf("Status = %q", r.Status)
	}
	if r.Solution == nil || r.Solution.URL != "https://example.com/" {
		t.Errorf("Solution = %+v", r.Solution)
	}
}

func TestNewError(t *testing.T) {
	r := NewError("boom", "1.0.0")
	if r.Status != StatusError {
		t.Errorf("Status = %q", r.Status)
	}
	if r.Message != "boom" {
		t.Errorf("Message = %q", r.Message)
	}
}
