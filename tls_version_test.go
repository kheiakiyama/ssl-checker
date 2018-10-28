package main

import (
	"testing"
)

func TestTLS10(t *testing.T) {
	t.Parallel()
	result := checkHost("tls-v1-0.badssl.com:1010")
	if !result.Version.TLS10 {
		t.Errorf("got: %v\nwant: %v", result.Version.TLS10, true)
	}
	result = checkHost("tls-v1-1.badssl.com:1011")
	if result.Version.TLS10 {
		t.Errorf("got: %v\nwant: %v", result.Version.TLS10, false)
	}
}

func TestTLS11(t *testing.T) {
	t.Parallel()
	result := checkHost("tls-v1-1.badssl.com:1011")
	if !result.Version.TLS11 {
		t.Errorf("got: %v\nwant: %v", result.Version.TLS11, true)
	}
	result = checkHost("tls-v1-2.badssl.com:1012")
	if result.Version.TLS11 {
		t.Errorf("got: %v\nwant: %v", result.Version.TLS11, false)
	}
}

func TestTLS12(t *testing.T) {
	t.Parallel()
	result := checkHost("tls-v1-2.badssl.com:1012")
	if !result.Version.TLS12 {
		t.Errorf("got: %v\nwant: %v", result.Version.TLS12, true)
	}
	result = checkHost("tls-v1-1.badssl.com:1011")
	if result.Version.TLS12 {
		t.Errorf("got: %v\nwant: %v", result.Version.TLS12, false)
	}
}
