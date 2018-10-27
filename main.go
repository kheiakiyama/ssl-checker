package main

import (
	"fmt"
	"net/http"
	"time"
)

type TLSState struct {
	Enabled          bool
	HSTSEnabled      bool
	Version          TLSVersionStates
	Cliper           CliperStates
	CurvePreferences CurvePreferencesStates
	ExpireDateUtc    time.Time
}

type TLSVersionStates struct {
	SSL30 bool
	TLS10 bool
	TLS11 bool
	TLS12 bool
}

type CliperStates struct {
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

type CurvePreferencesStates struct {
	X25519    bool
	CurveP256 bool
	CurveP384 bool
	CurveP521 bool
}

func main() {
	resp, _ := http.Get("https://google.co.jp")
	expireUTCTime := resp.TLS.PeerCertificates[0].NotAfter
	fmt.Println(resp.TLS.Version)
	fmt.Println(resp.TLS.CipherSuite)
	fmt.Println(resp.TLS.NegotiatedProtocol)
	expireJSTTime := expireUTCTime.In(time.FixedZone("Asia/Tokyo", 9*60*60))
	expireDate := expireJSTTime.Format("2006/01/02 15:04")
	fmt.Println(expireDate)
}
