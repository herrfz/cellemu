package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
)

func SHA256HMACGenerate(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sha256Mac := mac.Sum(nil)
	return sha256Mac[:8] // truncate to first 8 Bytes
}

func SHA256HMACVerify(key, data, msgmac []byte) ([]byte, bool) {
	expected := SHA256HMACGenerate(key, data)
	return expected, hmac.Equal(msgmac, expected)
}
