package main

import (
	"net/http"
)

type SSLCheckBasic struct {
}

func (check *SSLCheckBasic) CreateClient() (client *http.Client) {
	tr := &http.Transport{}
	return &http.Client{Transport: tr}
}

func (check *SSLCheckBasic) Pass(response *http.Response, result *TLSState) {
	result.Enabled = true
	result.ExpireDateUtc = response.TLS.PeerCertificates[0].NotAfter
}
