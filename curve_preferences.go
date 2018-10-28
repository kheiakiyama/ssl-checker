package main

import (
	"crypto/tls"
	"net/http"
)

type CurvePreferencesStates struct {
	X25519    bool
	CurveP256 bool
	CurveP384 bool
	CurveP521 bool
}

func GetCurvePreferenceCheck() []SSLCheck {
	return []SSLCheck{
		&SSLCheckCurvePreference{CurvePreference: tls.CurveP256},
		&SSLCheckCurvePreference{CurvePreference: tls.CurveP384},
		&SSLCheckCurvePreference{CurvePreference: tls.CurveP521},
		&SSLCheckCurvePreference{CurvePreference: tls.X25519},
	}
}

type SSLCheckCurvePreference struct {
	CurvePreference tls.CurveID
}

func (check *SSLCheckCurvePreference) CreateClient() (client *http.Client) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			CurvePreferences: []tls.CurveID{
				check.CurvePreference,
			},
		},
	}
	return &http.Client{Transport: tr}
}

func (check *SSLCheckCurvePreference) Pass(response *http.Response, result *TLSState) {
	switch check.CurvePreference {
	case tls.CurveP256:
		result.CurvePreferences.CurveP256 = true
	case tls.CurveP384:
		result.CurvePreferences.CurveP384 = true
	case tls.CurveP521:
		result.CurvePreferences.CurveP521 = true
	case tls.X25519:
		result.CurvePreferences.X25519 = true
	}
}
