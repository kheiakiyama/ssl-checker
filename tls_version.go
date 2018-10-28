package main

import (
	"crypto/tls"
	"net/http"
)

type TLSVersionStates struct {
	SSL30 bool
	TLS10 bool
	TLS11 bool
	TLS12 bool
}

func GetTLSVersionCheck() []SSLCheck {
	return []SSLCheck{
		&SSLCheckVersion{Version: tls.VersionSSL30},
		&SSLCheckVersion{Version: tls.VersionTLS10},
		&SSLCheckVersion{Version: tls.VersionTLS11},
		&SSLCheckVersion{Version: tls.VersionTLS12},
	}
}

type SSLCheckVersion struct {
	Version uint16
}

func (check *SSLCheckVersion) CreateClient() (client *http.Client) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: check.Version, MaxVersion: check.Version},
	}
	return &http.Client{Transport: tr}
}

func (check *SSLCheckVersion) Pass(result *TLSState) {
	switch check.Version {
	case tls.VersionSSL30:
		result.Version.SSL30 = true
	case tls.VersionTLS10:
		result.Version.TLS10 = true
	case tls.VersionTLS11:
		result.Version.TLS11 = true
	case tls.VersionTLS12:
		result.Version.TLS12 = true
	}
}
