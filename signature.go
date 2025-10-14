package cryptography

import (
	"crypto/rand"
	"encoding/base64"

	dilithium "github.com/cloudflare/circl/sign/dilithium/mode2"
)

func GenerateSignatureKeyPair() (string, string, error) {
	signaturePublic, signaturePrivate, err := dilithium.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	signaturePrivateBytes, err := signaturePrivate.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	signaturePrivateStr := base64.StdEncoding.EncodeToString(signaturePrivateBytes)
	signaturePublicBytes, err := signaturePublic.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	signaturePublicStr := base64.StdEncoding.EncodeToString(signaturePublicBytes)
	return signaturePublicStr, signaturePrivateStr, nil
}
