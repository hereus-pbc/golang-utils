package cryptography

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"strings"
	"time"
)

func GenerateTOTP(secret string, period int64) (string, error) {
	secret = strings.ToUpper(secret)
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", err
	}
	counter := time.Now().Unix() / period
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	h := hmac.New(sha256.New, key)
	h.Write(buf[:])
	hash := h.Sum(nil)
	offset := hash[len(hash)-1] & 0x0F
	code := (int(hash[offset])&0x7F)<<24 |
		(int(hash[offset+1])&0xFF)<<16 |
		(int(hash[offset+2])&0xFF)<<8 |
		(int(hash[offset+3]) & 0xFF)
	code = code % 1000000
	return padCode(code), nil
}

func padCode(code int) string {
	if code < 100000 {
		return "0" + padCode(code+100000)
	}
	return string([]byte{'0' + byte(code/100000%10), '0' + byte(code/10000%10), '0' + byte(code/1000%10), '0' + byte(code/100%10), '0' + byte(code/10%10), '0' + byte(code%10)})
}
