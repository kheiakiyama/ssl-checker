package main

import (
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

func getAllCheck() []SSLCheck {
	result := GetTLSVersionCheck()
	return result
}

func checkHost(host string) (result TLSState) {
	result = TLSState{Host: host}
	checkItems := getAllCheck()
	for _, item := range checkItems {
		client := item.CreateClient()
		_, err := client.Get("https://" + host + "/")
		if err == nil {
			item.Pass(&result)
		}
	}
	return result
}

func main() {
	host := flag.String("host", "example.com:443", "example.com:443")
	flag.Parse()
	result := checkHost(*host)
	json, err := json.Marshal(&result)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(json))
}
