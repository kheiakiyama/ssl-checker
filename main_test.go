package main

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	println("before all...")
	if !setUp() {
		os.Exit(1)
	}
	v := m.Run()
	println("after all...")
	if v == 0 && !tearDown() {
		os.Exit(1)
	}
	os.Exit(v)
}

func setUp() bool {
	return true
}

func tearDown() bool {
	return true
}

func TestTLS12(t *testing.T) {
	result := checkHost("tls-v1-2.badssl.com:1012")
	if !result.Version.TLS12 {
		t.Errorf("got: %v\nwant: %v", result.Version.TLS12, true)
	}
	result = checkHost("tls-v1-1.badssl.com:1011")
	if result.Version.TLS12 {
		t.Errorf("got: %v\nwant: %v", result.Version.TLS12, false)
	}
}
