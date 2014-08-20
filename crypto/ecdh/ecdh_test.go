package ecdh

import (
	"bytes"
	"math/big"
	"testing"
)

var (
	// http://tools.ietf.org/html/rfc5114#appendix-A.6
	dA, _   = new(big.Int).SetString("814264145F2F56F2E96A8E337A1284993FAF432A5ABCE59E867B7291D507A3AF", 16)
	x_qA, _ = new(big.Int).SetString("2AF502F3BE8952F2C9B5A8D4160D09E97165BE50BC42AE4A5E8D3B4BA83AEB15", 16)
	y_qA, _ = new(big.Int).SetString("EB0FAF4CA986C4D38681A0F9872D79D56795BD4BFF6E6DE3C0F5015ECE5EFD85", 16)
	pub_A   = append(x_qA.Bytes(), y_qA.Bytes()...)

	dB, _   = new(big.Int).SetString("2CE1788EC197E096DB95A200CC0AB26A19CE6BCCAD562B8EEE1B593761CF7F41", 16)
	x_qB, _ = new(big.Int).SetString("B120DE4AA36492795346E8DE6C2C8646AE06AAEA279FA775B3AB0715F6CE51B0", 16)
	y_qB, _ = new(big.Int).SetString("9F1B7EECE20D7B5ED8EC685FA3F071D83727027092A8411385C34DDE5708B2B6", 16)
	pub_B   = append(x_qB.Bytes(), y_qB.Bytes()...)

	x_Z, _ = new(big.Int).SetString("DD0F5396219D1EA393310412D19A08F1F5811E9DC8EC8EEA7F80D21C820C2788", 16)
	// y_Z, _ = new(big.Int).SetString("0357DCCD4C804D0D8D33AA42B848834AA5605F9AB0D37239A115BBB647936F50", 16)
	// PolarSSL shared secret
	ZZ = x_Z.Bytes()
)

func TestGenPubKey(t *testing.T) {
	if x := GeneratePublic(dA.Bytes()); !bytes.Equal(x, pub_A) {
		t.Errorf("test fails")
	}

	if x := GeneratePublic(dB.Bytes()); !bytes.Equal(x, pub_B) {
		t.Errorf("test fails")
	}
}

func TestCheckPubKey(t *testing.T) {
	keys := make([][]byte, 2)
	keys[0] = pub_A
	keys[1] = pub_B
	for _, key := range keys {
		if !CheckPublic(key) {
			t.Errorf("test fails")
		}
	}
}

func TestGenSecret(t *testing.T) {
	if x, _ := GenerateSecret(dA.Bytes(), pub_B); !bytes.Equal(x, ZZ) {
		t.Errorf("test fails")
	}

	if x, _ := GenerateSecret(dB.Bytes(), pub_A); !bytes.Equal(x, ZZ) {
		t.Errorf("test fails")
	}
}
