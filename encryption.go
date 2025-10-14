package cryptography

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
)

func GenerateEncryptionKeyPair() (string, string, error) {
	encryptionPublic, encryptionPrivate, err := kyber512.GenerateKeyPair(rand.Reader)
	if err != nil {
		return "", "", err
	}
	encPrivateBytes, err := encryptionPrivate.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	encPrivateStr := base64.StdEncoding.EncodeToString(encPrivateBytes)
	encPublicBytes, err := encryptionPublic.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	encPublicStr := base64.StdEncoding.EncodeToString(encPublicBytes)
	return encPublicStr, encPrivateStr, nil
}
