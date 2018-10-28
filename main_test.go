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
