package randomizer

import (
	"crypto/rand"
	"encoding/hex"
)

func RandomGivenByte(num int) []byte {
	b := make([]byte, num)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func Random64Byte() []byte {
	return RandomGivenByte(64)
}

func Random128ByteString() string {
	return hex.EncodeToString(RandomGivenByte(128))
}
