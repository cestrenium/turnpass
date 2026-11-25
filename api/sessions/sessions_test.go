package sessions

import (
	"testing"
	"time"
)

func TestCreateAndGet(t *testing.T) {
	s := New(time.Minute)
	sess, err := s.Create("a", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sess.ID != "a" {
		t.Errorf("ID = %q", sess.ID)
	}
	got, err := s.Get("a", false)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "a" {
		t.Errorf("ID = %q", got.ID)
	}
}

func TestCreateDuplicate(t *testing.T) {
	s := New(time.Minute)
	if _, err := s.Create("a", 0); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Create("a", 0); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestGetMissing(t *testing.T) {
	s := New(time.Minute)
	if _, err := s.Get("nope", false); err == nil {
		t.Fatal("expected not-found error")
	}
	if _, err := s.Get("nope", true); err != nil {
		t.Fatalf("Get(createMissing=true): %v", err)
	}
}

func TestListAndDestroy(t *testing.T) {
	s := New(time.Minute)
	s.Create("a", 0)
	s.Create("b", 0)
	if got := s.List(); len(got) != 2 {
		t.Errorf("List = %d, want 2", len(got))
	}
	if err := s.Destroy("a"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if got := s.List(); len(got) != 1 {
		t.Errorf("List after destroy = %d, want 1", len(got))
	}
	if err := s.Destroy("a"); err == nil {
		t.Error("Destroy of missing should error")
	}
}

func TestExpiration(t *testing.T) {
	s := New(time.Minute)
	s.Create("a", 0)
	// Force expiration.
	s.mu.Lock()
	s.sessions["a"].Expires = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if _, err := s.Get("a", false); err == nil {
		t.Fatal("expected expired error")
	}
	if got := s.List(); len(got) != 0 {
		t.Errorf("List = %d, want 0 after expiry", len(got))
	}
}
