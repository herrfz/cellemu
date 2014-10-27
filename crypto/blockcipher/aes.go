package blockcipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// encrypt AES-CBC
// the composition of these functions doesn't feel right, to be refactored
func aesEncryptCBC(key, plaintext, iv []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext length is not a multiple of AES block")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	copy(ciphertext[:aes.BlockSize], iv)

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func AESEncryptCBC(key, plaintext []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	return aesEncryptCBC(key, plaintext, iv)
}

func aesEncryptCBCPKCS7(key, plaintext, iv []byte) ([]byte, error) {
	padlen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padbyte := byte(padlen)

	for i := 0; i < padlen; i++ {
		plaintext = append(plaintext, padbyte)
	}

	return aesEncryptCBC(key, plaintext, iv)
}

func AESEncryptCBCPKCS7(key, plaintext []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	return aesEncryptCBCPKCS7(key, plaintext, iv)
}

// decrypt AES-CBC of a ciphertext
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
