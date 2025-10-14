package cryptography

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

func ComputeSha256DigestBase64(data []byte) string {
	hash := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func VerifyHttpSignature(r *http.Request, sigHeader string, actorPublicKeyPem string, domain string) error {
	params := parseSigHeader(sigHeader)

	headers := strings.Split(params["headers"], " ")
	var signingLines []string
	for _, h := range headers {
		hLower := strings.ToLower(h)
		switch hLower {
		case "(request-target)":
			signingLines = append(signingLines,
				fmt.Sprintf("(request-target): %s %s", strings.ToLower(r.Method), r.URL.RequestURI()))
		default:
			val := (func() string {
				if h == "host" {
					return domain
				} else {
					return r.Header.Get(h)
				}
			})()
			if val == "" {
				return fmt.Errorf("missing signed header %q", h)
			}
			signingLines = append(signingLines, fmt.Sprintf("%s: %s", hLower, val))
		}
	}
	signingString := strings.Join(signingLines, "\n")

	// Decode the Base64-encoded signature
	sig, err := base64.StdEncoding.DecodeString(params["signature"])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Convert the PEM-encoded public key to rsa.PublicKey
	pubKey, err := PemToPublicKey(actorPublicKeyPem)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Compute the SHA-256 hash of the signing string
	hashed := sha256.Sum256([]byte(signingString))

	// Verify the signature using RSA PKCS#1 v1.5
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], sig)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func GenerateHttpSignature(r *http.Request, privateKey *rsa.PrivateKey, headers []string, keyId string, domain string) (string, error) {
	var signingLines []string
	for _, h := range headers {
		hLower := strings.ToLower(h)
		switch hLower {
		case "(request-target)":
			signingLines = append(signingLines,
				fmt.Sprintf("(request-target): %s %s", strings.ToLower(r.Method), r.URL.RequestURI()))
		default:
			val := (func() string {
				if h == "host" {
					return domain
				} else {
					return r.Header.Get(h)
				}
			})()
			if val == "" {
				return "", fmt.Errorf("missing header %q for signing", h)
			}
			signingLines = append(signingLines, fmt.Sprintf("%s: %s", hLower, val))
		}
	}

	signingString := strings.Join(signingLines, "\n")
	hashed := sha256.Sum256([]byte(signingString))

	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Construct signature header
	sigHeader := fmt.Sprintf(`keyId="%s",algorithm="rsa-sha256",headers="%s",signature="%s"`,
		keyId,
		strings.Join(headers, " "),
		sigB64,
	)

	return sigHeader, nil
}