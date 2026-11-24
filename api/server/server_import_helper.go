package server

import "net/url"

func init() {
	_ = url.Parse // keep import alive for tests in middleware_test.go
}
