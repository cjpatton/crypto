package ecdsa

import (
	"crypto/elliptic"
	//"crypto/sha"
	"crypto/rand"
	"math/big"
)

type PublicKey struct {
	params *elliptic.CurveParams
	x, y   *big.Int
}

type SecretKey struct {
	PublicKey
	k []byte
}

func NewKeyPair(curve elliptic.Curve) (*PublicKey, *SecretKey, error) {
	k, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pk := &PublicKey{curve.Params(), x, y}
	sk := &SecretKey{*pk, k}
	return pk, sk, nil
}

func (sk *SecretKey) Sign(in []byte) ([]byte, error) {
	return nil, nil
}

func (pk *PublicKey) Verify(in, sig []byte) bool {
	return false
}
