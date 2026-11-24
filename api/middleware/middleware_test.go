package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRecovery(t *testing.T) {
	h := Recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, &http.Request{Method: "GET", URL: mustParse("/x")})
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Code = %d, want 500", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "internal server error") {
		t.Errorf("Body = %q", rr.Body.String())
	}
}

func TestTimeout(t *testing.T) {
	h := Timeout(10*time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(100 * time.Millisecond):
			w.WriteHeader(200)
		}
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, &http.Request{Method: "GET", URL: mustParse("/x")})
	if rr.Code == 200 {
		t.Errorf("Code = 200, want non-200 (timeout)")
	}
}

func TestLogging(t *testing.T) {
	h := Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, &http.Request{Method: "GET", URL: mustParse("/x")})
	if rr.Code != 204 {
		t.Errorf("Code = %d, want 204", rr.Code)
	}
}

func mustParse(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}
