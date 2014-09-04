package blockcipher

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type testpair struct {
	key, iv, ct, pt string
}

// Test vectors: http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-cbc-128
var tests = []testpair{
	{"2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090A0B0C0D0E0F", "7649abac8119b246cee98e9b12e9197d", "6bc1bee22e409f96e93d7e117393172a"},
	{"2b7e151628aed2a6abf7158809cf4f3c", "7649ABAC8119B246CEE98E9B12E9197D", "5086cb9b507219ee95db113a917678b2", "ae2d8a571e03ac9c9eb76fac45af8e51"},
	{"2b7e151628aed2a6abf7158809cf4f3c", "5086CB9B507219EE95DB113A917678B2", "73bed6b8e3c1743b7116e69e22229516", "30c81c46a35ce411e5fbc1191a0a52ef"},
	{"2b7e151628aed2a6abf7158809cf4f3c", "73BED6B8E3C1743B7116E69E22229516", "3ff1caa1681fac09120eca307586e1a7", "f69f2445df4f9b17ad2b417be66c3710"},
}

var failtests = []testpair{
	{"2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090A0B0C0D0E0F", "7649abac8119b246cee98e9b12e9197dde", "6bc1bee22e409f96e93d7e117393172a"},
	{"2b7e151628aed2a6abf7158809cf4f3c", "7649ABAC8119B246CEE98E9B12E9197D", "5086cb9b507219ee95db113a917678b2ad", "ae2d8a571e03ac9c9eb76fac45af8e51"},
	{"2b7e151628aed2a6abf7158809cf4f3c", "5086CB9B507219EE95DB113A917678B2", "73bed6b8e3c1743b7116e69e22229516beef", "30c81c46a35ce411e5fbc1191a0a52ef"},
	{"2b7e151628aed2a6abf7158809cf4f3c", "73BED6B8E3C1743B7116E69E22229516", "3ff1caa1681fac09120eca307586e1a7cafe", "f69f2445df4f9b17ad2b417be66c3710"},
}

// Test vectors: https://github.com/geertj/bluepass/blob/master/tests/vectors/aes-cbc-pkcs7.txt
var pkcstests = []testpair{
	{"ac5800ac3cb59c7c14f36019e43b44fe", "f013ce1ec901b5b60a85a986b3b72eba", "e8a846fd9718507371604504d4ca1ac7", "f6cee5ff28fd"},
	{"24c4328aeffc0ca354a3215a3da23a38", "c43c6269bb8c1dbba3bc22b7ba7e24b1", "009e935f3fe4d57b57fc3127a8873d8c", "76cdfdf52a9753"},
	{"4035227440a779dbd1ed75c6ae78cef5", "8faff161a5ec06e051066a571d1729d9", "b3d8df2c3147b0752a7e6bbbcc9d5758", "b103c928531d8875"},
	{"507008732ea559915e5e45d9710e3ed2", "342b22c1cbf1c92b8e63a38de99ffb09", "c11a034ed324aeae9cd5857ae4cd776f", "590b10224087872724"},
	{"a060441b1b7cc2af405be4f6f5c58e22", "429d3240207e77e9b9dade05426fe3cb", "b61ff0a956b420347daa25bb76964b51", "ccecfa22708b6d06439c"},
	{"721888e260b8925fe51183b88d65fb17", "5308c58068cbc05a5461a43bf744b61e", "3ee8bdb21b00e0103ccbf9afb9b5bd9a", "8ff539940bae985f2f88f3"},
	{"80ba985c93763f99ff4be6cdee6ab977", "ca8e99719be2e842e81bf15c606bb916", "3e087f92a998ad531e0ff8e996098382", "4c84974b5b2109d5bc90e1f0"},
	{"1fe107d14dd8b152580f3dea8591fc3b", "7b6070a896d41d227cc0cebbd92d797e", "a4bfd6586344bcdef94f09d871ca8a16", "13eb26baf2b688574cadac6dba"},
	{"4d3dae5d9e19950f278b0dd4314e3768", "80190b58666f15dbaf892cf0bceb2a50", "2b166eae7a2edfea7a482e5f7377069e", "5fcb46a197ddf80a40f94dc21531"},
	{"0784fa652e733cb699f250b0df2c4b41", "106519760fb3ef97e1ccea073b27122d", "56a8e0c3ee3315f913693c0ca781e917", "6842455a2992c2e5193056a5524075"},
	{"04952c3fcf497a4d449c41e8730c5d9a", "53549bf7d5553b727458c1abaf0ba167", "7fa290322ca7a1a04b61a1147ff20fe66fde58510a1d0289d11c0ddf6f4decfd", "c9a44f6f75e98ddbca7332167f5c45e3"},
	{"2ae7081caebe54909820620a44a60a0f", "fc5e783fbe7be12f58b1f025d82ada50", "7944957a99e473e2c07eb496a83ec4e55db2fb44ebdd42bb611e0def29b23a73ac37eb0f4f5d86f090f3ddce3980425a", "1ba93ee6f83752df47909585b3f28e56693f89e169d3093eee85175ea3a46cd3"},
	{"898be9cc5004ed0fa6e117c9a3099d31", "9dea7621945988f96491083849b068df", "e232cd6ef50047801ee681ec30f61d53cfd6b0bca02fd03c1b234baa10ea82ac9dab8b960926433a19ce6dea08677e34", "0397f4f6820b1f9386f14403be5ac16e50213bd473b4874b9bcbf5f318ee686b1d"},
	{"be0d465f8004d636d90e3f9f6a9063d2", "748869ca52f219b4764c9ae986fa821b", "790511b7776b98be3d0a4861b7f1c8bb", ""},
	{"893123f2d57b6e2c39e2f10d3ff818d1", "64be1b06ea7453ed2df9a79319d5edc5", "7067c4cb6dfc69df949c2f39903c9310", "44afb9a64ac896c2"},
}

func TestAESDecryptCBC(t *testing.T) {
	for _, pair := range tests {
		key, _ := hex.DecodeString(pair.key)
		iv, _ := hex.DecodeString(pair.iv)
		ct, _ := hex.DecodeString(pair.ct)
		pt, _ := hex.DecodeString(pair.pt)
		cipher := append(iv, ct...)
		if plain, _ := AESDecryptCBC(key, cipher); !bytes.Equal(plain, pt) {
			t.Error("expected:", hex.EncodeToString(pt), "got:", hex.EncodeToString(plain))
		}
	}

	for _, pair := range failtests {
		key, _ := hex.DecodeString(pair.key)
		iv, _ := hex.DecodeString(pair.iv)
		ct, _ := hex.DecodeString(pair.ct)
		pt, _ := hex.DecodeString(pair.pt)
		cipher := append(iv, ct...)
		if plain, err := AESDecryptCBC(key, cipher); err == nil {
			t.Error("expected error, got nil, expected:", hex.EncodeToString(pt), "decrypted plaintext", hex.EncodeToString(plain))
		}
	}
}

func TestAESDecryptCBCPKCS7(t *testing.T) {
	for _, pair := range pkcstests {
		key, _ := hex.DecodeString(pair.key)
		iv, _ := hex.DecodeString(pair.iv)
		ct, _ := hex.DecodeString(pair.ct)
		pt, _ := hex.DecodeString(pair.pt)
		cipher := append(iv, ct...)
		if plain, _ := AESDecryptCBCPKCS7(key, cipher); !bytes.Equal(plain, pt) {
			t.Error("expected:", hex.EncodeToString(pt), "got:", hex.EncodeToString(plain))
		}
	}
}
