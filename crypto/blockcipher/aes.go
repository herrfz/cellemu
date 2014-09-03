package blockcipher

import (
	"crypto/aes"
	"crypto/cipher"
)

// decrypt AES-CBC plaintext
func AESDecryptCBC(key, ciphertext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	tmp_ct := make([]byte, len(ciphertext))
	copy(tmp_ct, ciphertext)
	iv := tmp_ct[:aes.BlockSize]
	pt := tmp_ct[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(pt, pt)
	return pt, nil
}

// decrypt AES-CBC plaintext, assuming PKCS#7 padding
func AESDecryptCBCPKCS7(key, ciphertext []byte) ([]byte, error) {
	pt, err := AESDecryptCBC(key, ciphertext)
	if err != nil {
		return nil, err
	}

	padlen := int(pt[len(pt)])
	return pt[:len(pt)-padlen], nil
}
