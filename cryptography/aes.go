package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("pkcs7Unpad: data is empty")
	}
	padding := int(data[length-1])
	if padding == 0 || padding > length {
		return nil, fmt.Errorf("pkcs7Unpad: invalid padding")
	}
	for i := 0; i < padding; i++ {
		if data[length-1-i] != byte(padding) {
			return nil, fmt.Errorf("pkcs7Unpad: invalid padding bytes")
		}
	}
	return data[:length-padding], nil
}

func AesEncryptBytes(password, content []byte) (string, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return "", err
	}
	key := pbkdf2.Key(password, salt, 100000, 32, sha256.New)
	iv := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(content, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)
	return hex.EncodeToString(salt) + hex.EncodeToString(iv) + hex.EncodeToString(ciphertext), nil
}

func AesDecryptBytes(password []byte, encrypted string) ([]byte, error) {
	salt, err := hex.DecodeString(encrypted[:32])
	if err != nil {
		return nil, err
	}
	iv, err := hex.DecodeString(encrypted[32:64])
	if err != nil {
		return nil, err
	}
	ciphertext, err := hex.DecodeString(encrypted[64:])
	if err != nil {
		return nil, err
	}
	key := pbkdf2.Key(password, salt, 100000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	padded := make([]byte, len(ciphertext))
	mode.CryptBlocks(padded, ciphertext)
	unpadded, err := pkcs7Unpad(padded)
	if err != nil {
		return nil, err
	}
	return unpadded, nil
}
