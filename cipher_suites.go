package main

import (
	"crypto/tls"
	"net/http"
)

type CiperStates struct {
	TLS_RSA_WITH_RC4_128_SHA                bool
	TLS_RSA_WITH_3DES_EDE_CBC_SHA           bool
	TLS_RSA_WITH_AES_128_CBC_SHA            bool
	TLS_RSA_WITH_AES_256_CBC_SHA            bool
	TLS_RSA_WITH_AES_128_CBC_SHA256         bool
	TLS_RSA_WITH_AES_128_GCM_SHA256         bool
	TLS_RSA_WITH_AES_256_GCM_SHA384         bool
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA        bool
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    bool
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    bool
	TLS_ECDHE_RSA_WITH_RC4_128_SHA          bool
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     bool
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      bool
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      bool
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 bool
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   bool
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   bool
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 bool
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   bool
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 bool
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305    bool
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305  bool
}

func GetCipherSuitesCheck() []SSLCheck {
	return []SSLCheck{
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_RSA_WITH_RC4_128_SHA},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_RSA_WITH_AES_256_CBC_SHA},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_RSA_WITH_AES_128_CBC_SHA256},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_RSA_WITH_AES_256_GCM_SHA384},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
		&SSLCheckCipherSuite{CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305},
	}
}

type SSLCheckCipherSuite struct {
	CipherSuite uint16
}

func (check *SSLCheckCipherSuite) CreateClient() (client *http.Client) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{check.CipherSuite}},
	}
	return &http.Client{Transport: tr}
}

func (check *SSLCheckCipherSuite) Pass(response *http.Response, result *TLSState) {
	switch check.CipherSuite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		result.Cliper.TLS_RSA_WITH_RC4_128_SHA = true
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		result.Cliper.TLS_RSA_WITH_3DES_EDE_CBC_SHA = true
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		result.Cliper.TLS_RSA_WITH_AES_128_CBC_SHA = true
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		result.Cliper.TLS_RSA_WITH_AES_256_CBC_SHA = true
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		result.Cliper.TLS_RSA_WITH_AES_128_CBC_SHA256 = true
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		result.Cliper.TLS_RSA_WITH_AES_128_GCM_SHA256 = true
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		result.Cliper.TLS_RSA_WITH_AES_256_GCM_SHA384 = true
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		result.Cliper.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = true
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		result.Cliper.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = true
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		result.Cliper.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = true
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		result.Cliper.TLS_ECDHE_RSA_WITH_RC4_128_SHA = true
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		result.Cliper.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = true
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		result.Cliper.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = true
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		result.Cliper.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = true
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		result.Cliper.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = true
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		result.Cliper.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = true
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		result.Cliper.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = true
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		result.Cliper.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = true
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		result.Cliper.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = true
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		result.Cliper.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = true
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		result.Cliper.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 = true
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		result.Cliper.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = true
	}
}
