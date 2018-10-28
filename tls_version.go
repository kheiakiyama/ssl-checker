package main

import (
	"crypto/tls"
	"net/http"
)

type TLSVersionStates struct {
	TLS10 bool
	TLS11 bool
	TLS12 bool
}

func GetTLSVersionCheck() []SSLCheck {
	return []SSLCheck{
		&SSLCheckTLS10{},
		&SSLCheckTLS11{},
		&SSLCheckTLS12{},
	}
}

type SSLCheckTLS10 struct {
}

func (check *SSLCheckTLS10) CreateClient() (client *http.Client) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10},
	}
	return &http.Client{Transport: tr}
}

func (check *SSLCheckTLS10) Pass(result *TLSState) {
	result.Version.TLS10 = true
}

type SSLCheckTLS11 struct {
}

func (check *SSLCheckTLS11) CreateClient() (client *http.Client) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11},
	}
	return &http.Client{Transport: tr}
}

func (check *SSLCheckTLS11) Pass(result *TLSState) {
	result.Version.TLS11 = true
}

type SSLCheckTLS12 struct {
}

func (check *SSLCheckTLS12) CreateClient() (client *http.Client) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
	}
	return &http.Client{Transport: tr}
}

func (check *SSLCheckTLS12) Pass(result *TLSState) {
	result.Version.TLS12 = true
}
