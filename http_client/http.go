package http_client

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/hereus-pbc/golang-utils/cryptography"
)

type Signature struct {
	PrivateKey *rsa.PrivateKey
	Headers    []string
	KeyId      string
}

func DoHttpJsonRequest(method string, url string, requestBody any, headers map[string]string, signature *Signature) (*http.Response, error) {
	client := &http.Client{}
	var req *http.Request
	var err error
	remoteHost := strings.Split(strings.TrimPrefix(url, "https://"), "/")[0]
	if requestBody == nil {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			return nil, err
		}
	} else {
		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest(method, url, strings.NewReader(string(jsonData)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Digest", "SHA-256="+cryptography.ComputeSha256DigestBase64(jsonData))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Host", remoteHost)
	req.Header.Set("Date", time.Now().In(time.FixedZone("GMT", 0)).Format(time.RFC1123))
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if signature != nil {
		httpSignature, err := cryptography.GenerateHttpSignature(req, signature.PrivateKey, signature.Headers, signature.KeyId, remoteHost)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Signature", httpSignature)
	}
	return client.Do(req)
}
