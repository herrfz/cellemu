package ecdh

import (
	ec "crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	// RFC 5114
	P, _     = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
	N, _     = new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
	B, _     = new(big.Int).SetString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
	Gx, _    = new(big.Int).SetString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
	Gy, _    = new(big.Int).SetString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
	BitSize  = 256
	ByteSize = BitSize / 8

	curve = ec.CurveParams{P, N, B, Gx, Gy, BitSize}
)

func GeneratePrivate() ([]byte, error) {
	pk, err := rand.Int(rand.Reader, curve.N)
	return pk.Bytes(), err
}

func GeneratePublic(privkey []byte) []byte {
	px, py := curve.ScalarBaseMult(privkey)
	return append(px.Bytes(), py.Bytes()...)
}

func CheckPublic(pubkey []byte) bool {
	px := new(big.Int).SetBytes(pubkey[:ByteSize])
	py := new(big.Int).SetBytes(pubkey[ByteSize:])
	// TODO check if infinity
	// TODO check if in range
	return curve.IsOnCurve(px, py)
}

func GenerateSecret(privkey, otherpubkey []byte) ([]byte, error) {
	if !CheckPublic(otherpubkey) {
		err := errors.New("invalid public key")
		return nil, err
	}

	px := new(big.Int).SetBytes(otherpubkey[:ByteSize])
	py := new(big.Int).SetBytes(otherpubkey[ByteSize:])
	secx, secy := curve.ScalarMult(px, py, privkey)
	return append(secx.Bytes(), secy.Bytes()...), nil
}
