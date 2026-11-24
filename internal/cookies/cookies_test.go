package cookies

import (
	"net/url"
	"testing"
)

func TestSetAndRetrieve(t *testing.T) {
	j := New()
	u, _ := url.Parse("https://example.com/path/page")
	j.SetCookie(u, "session=abc; Path=/")
	cs := j.Cookies(u)
	if len(cs) != 1 {
		t.Fatalf("Cookies = %d, want 1", len(cs))
	}
	if cs[0].Name != "session" || cs[0].Value != "abc" {
		t.Errorf("cookie = %+v", cs[0])
	}
	if j.CookieHeader(u) != "session=abc" {
		t.Errorf("CookieHeader = %q", j.CookieHeader(u))
	}
}

func TestDomainMatching(t *testing.T) {
	j := New()
	root, _ := url.Parse("https://example.com/")
	j.SetCookie(root, "id=1; Domain=example.com; Path=/")
	sub, _ := url.Parse("https://sub.example.com/")
	if got := j.Cookies(sub); len(got) != 1 {
		t.Errorf("subdomain should see root cookie, got %d", len(got))
	}
	other, _ := url.Parse("https://other.com/")
	if got := j.Cookies(other); len(got) != 0 {
		t.Errorf("other.com should see no cookies, got %d", len(got))
	}
}

func TestPathMatching(t *testing.T) {
	j := New()
	root, _ := url.Parse("https://example.com/app/page")
	j.SetCookie(root, "a=1; Path=/app")
	page, _ := url.Parse("https://example.com/app/page/sub")
	if got := j.Cookies(page); len(got) != 1 {
		t.Errorf("/app/page/sub should see /app cookie, got %d", len(got))
	}
	other, _ := url.Parse("https://example.com/other")
	if got := j.Cookies(other); len(got) != 0 {
		t.Errorf("/other should not see /app cookie, got %d", len(got))
	}
}

func TestReplaceExisting(t *testing.T) {
	j := New()
	u, _ := url.Parse("https://example.com/")
	j.SetCookie(u, "k=v1; Path=/")
	j.SetCookie(u, "k=v2; Path=/")
	cs := j.Cookies(u)
	if len(cs) != 1 {
		t.Fatalf("Cookies = %d, want 1", len(cs))
	}
	if cs[0].Value != "v2" {
		t.Errorf("Value = %q, want v2", cs[0].Value)
	}
}

func TestSecureFlag(t *testing.T) {
	j := New()
	u, _ := url.Parse("https://example.com/")
	j.SetCookie(u, "s=1; Path=/; Secure")
	https, _ := url.Parse("https://example.com/")
	if got := j.Cookies(https); len(got) != 1 {
		t.Errorf("https should see Secure cookie, got %d", len(got))
	}
	http, _ := url.Parse("http://example.com/")
	if got := j.Cookies(http); len(got) != 0 {
		t.Errorf("http should not see Secure cookie, got %d", len(got))
	}
}

func TestClearAll(t *testing.T) {
	j := New()
	u, _ := url.Parse("https://example.com/")
	j.SetCookie(u, "a=1; Path=/")
	j.SetCookie(u, "b=2; Path=/")
	if j.Len() != 2 {
		t.Errorf("Len = %d, want 2", j.Len())
	}
	j.Clear()
	if j.Len() != 0 {
		t.Errorf("Len after Clear = %d, want 0", j.Len())
	}
}

func TestDefaultPath(t *testing.T) {
	cases := []struct {
		uri  string
		want string
	}{
		{"", "/"},
		{"foo", "/"},
		{"/", "/"},
		{"/page", "/"},
		{"/app/page", "/app"},
		{"/app/dir/page", "/app/dir"},
	}
	for _, c := range cases {
		if got := defaultPath(c.uri); got != c.want {
			t.Errorf("defaultPath(%q) = %q, want %q", c.uri, got, c.want)
		}
	}
}
