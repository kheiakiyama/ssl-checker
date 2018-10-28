package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"sync"
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
	var wg sync.WaitGroup
	for _, item := range checkItems {
		wg.Add(1)
		go func(item SSLCheck, result *TLSState) {
			defer wg.Done()
			client := item.CreateClient()
			_, err := client.Get("https://" + host + "/")
			if err == nil {
				item.Pass(result)
			}
		}(item, &result)
	}
	wg.Wait()
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
