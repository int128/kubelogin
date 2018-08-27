package auth

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

func generateState() (string, error) {
	var n uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", n), nil
}
