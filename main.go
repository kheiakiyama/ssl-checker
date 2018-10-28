package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"time"
)

type TLSState struct {
	Host             string
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

type SSLCheck interface {
	CreateClient() (client *http.Client)
	Pass(result *TLSState)
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

func checkHost(host *string) (result TLSState) {
	result = TLSState{Host: *host}
	var check SSLCheck = &SSLCheckTLS12{}
	client := check.CreateClient()
	_, err := client.Get("https://" + *host + "/")
	if err == nil {
		check.Pass(&result)
	}
	return result
}

func main() {
	host := flag.String("host", "example.com:443", "example.com:443")
	flag.Parse()
	result := checkHost(host)
	json, err := json.Marshal(&result)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(json))
}
