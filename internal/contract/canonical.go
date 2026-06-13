package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func CanonicalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

func Digest(value any) (string, error) {
	bytes, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}
