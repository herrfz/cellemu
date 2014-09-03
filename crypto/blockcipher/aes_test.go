package blockcipher

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type testpair struct {
	iv, ct, pt string
}

var tests = []testpair{
	{"000102030405060708090A0B0C0D0E0F", "7649abac8119b246cee98e9b12e9197d", "6bc1bee22e409f96e93d7e117393172a"},
	{"7649ABAC8119B246CEE98E9B12E9197D", "5086cb9b507219ee95db113a917678b2", "ae2d8a571e03ac9c9eb76fac45af8e51"},
	{"5086CB9B507219EE95DB113A917678B2", "73bed6b8e3c1743b7116e69e22229516", "30c81c46a35ce411e5fbc1191a0a52ef"},
	{"73BED6B8E3C1743B7116E69E22229516", "3ff1caa1681fac09120eca307586e1a7", "f69f2445df4f9b17ad2b417be66c3710"},
}

// Test vectors: http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-cbc-128
func TestAESDecryptCBC(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")

	for _, pair := range tests {
		iv, _ := hex.DecodeString(pair.iv)
		ct, _ := hex.DecodeString(pair.ct)
		pt, _ := hex.DecodeString(pair.pt)
		cipher := append(iv, ct...)
		if plain, _ := AESDecryptCBC(key, cipher); !bytes.Equal(plain, pt) {
			t.Error("expected:", pt, "got:", plain)
		}
	}
}
