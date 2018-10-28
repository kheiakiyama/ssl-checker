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
	Cliper           CiperStates
	CurvePreferences CurvePreferencesStates
	ExpireDateUtc    time.Time
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
	return append(
		GetTLSVersionCheck(),
		GetCipherSuitesCheck()...)
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
