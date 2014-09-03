package blockcipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
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

	if len(pt)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length is not a multiple of AES block")
	}

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

	padlen := int(pt[len(pt)-1])

	padcheck := byte(0x00)
	for i := len(pt) - 1; i < len(pt)-padlen; i-- {
		padcheck |= pt[i] ^ byte(padlen)
	}
	// take care of padding oracle!
	if padcheck != 0x00 {
		return nil, fmt.Errorf("incorrect padding format")
	}

	return pt[:len(pt)-padlen], nil
}
