package cryptography

import (
	"fmt"

	"github.com/hereus-pbc/golang-utils/randomizer"
)

func GenerateKek(password []byte) (string, error) {
	randomContent := randomizer.Random64Byte()
	ret, err := AesEncryptBytes(password, randomContent)
	if err != nil {
		return "", err
	}
	return ret, nil
}

func EncryptWithKek(password string, kek string, content []byte) (string, error) {
	l1, err := AesDecryptBytes([]byte(password), kek)
	if err != nil {
		return "", err
	}
	if len(l1) != 64 {
		return "", fmt.Errorf("invalid layer 2 content length: expected 64 bytes, got %d", len(l1))
	}
	ret, err := AesEncryptBytes(l1, content)
	if err != nil {
		return "", err
	}
	return ret, nil
}

func DecryptWithKek(password string, kek string, encrypted string) ([]byte, error) {
	l1, err := AesDecryptBytes([]byte(password), kek)
	if err != nil {
		return nil, err
	}
	if len(l1) != 64 {
		return nil, fmt.Errorf("invalid layer 2 content length: expected 64 bytes, got %d", len(l1))
	}
	return AesDecryptBytes(l1, encrypted)
}

func DeriveKek(oldPassword string, kek string, newPassword string) (string, error) {
	l1, err := AesDecryptBytes([]byte(oldPassword), kek)
	if err != nil {
		return "", err
	}
	if len(l1) != 64 {
		return "", fmt.Errorf("invalid layer 2 content length: expected 64 bytes, got %d", len(l1))
	}
	return AesEncryptBytes([]byte(newPassword), l1)
}
