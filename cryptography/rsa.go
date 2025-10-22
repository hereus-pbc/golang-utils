package cryptography

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

func RsaPemToPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bad public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

func RsaPemToPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bad private key: %w", err)
	}
	return private, nil
}

func RsaPublicKeyToPem(rsaPublicKey *rsa.PublicKey) (string, error) {
	rsaPublicDerBytes, err := x509.MarshalPKIXPublicKey(&rsaPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal RSA public key: %w", err)
	}
	rsaPublicPemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: rsaPublicDerBytes,
	}
	rsaPublicPemBytes := pem.EncodeToMemory(rsaPublicPemBlock)
	return string(rsaPublicPemBytes), nil
}

func RsaPrivateKeyToPem(rsaPrivateKey *rsa.PrivateKey) string {
	rsaPrivateDerBytes := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	rsaPrivatePemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: rsaPrivateDerBytes,
	}
	return string(pem.EncodeToMemory(rsaPrivatePemBlock))
}