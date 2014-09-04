package blockcipher

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
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
		return nil, fmt.Errorf("ciphertext length is not a multiple of AES block: %s",
			hex.EncodeToString(pt))
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

	// verify correct padding format; beware of padding oracle when doing this!
	// always encrypt-then-authenticate (i.e. authenticate-then-decrypt)!!
	padcheck := byte(0x00)
	for i := len(pt) - padlen; i < len(pt); i++ {
		padcheck |= pt[i] ^ byte(padlen)
	}
	if padcheck != 0x00 {
		return nil, fmt.Errorf("incorrect padding format")
	}

	return pt[:len(pt)-padlen], nil
}
