package identity

import (
	"crypto/sha256"
	"encoding/hex"
)

func MessageKey(from, returnPath, recipientIP, body string) string {
	h := sha256.New()
	for _, part := range []string{from, returnPath, recipientIP, body} {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func BodySHA(body string) string {
	digest := sha256.Sum256([]byte(body))
	return hex.EncodeToString(digest[:])
}
