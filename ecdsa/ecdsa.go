package ecdsa

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	h "hash"
	"math/big"
)

type PublicKey struct {
	curve elliptic.Curve
	hash  h.Hash
	x, y  *big.Int
}

type SecretKey struct {
	PublicKey
	priv *big.Int
}

type ecdsaSignature struct {
	R, S *big.Int
}

func NewKeyPair(curve elliptic.Curve, hash h.Hash) (*PublicKey, *SecretKey, error) {
	if hash.Size() < (curve.Params().BitSize >> 3) {
		return nil, nil, errors.New("hash output smaller than group field elements")
	}
	k, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pk := &PublicKey{curve, hash, x, y}
	sk := &SecretKey{*pk, new(big.Int)}
	sk.priv.SetBytes(k)
	return pk, sk, nil
}

func (sk *SecretKey) Sign(msg []byte) ([]byte, error) {

	r := new(big.Int)
	s := new(big.Int)
	z := new(big.Int)
	x1 := new(big.Int)
	zero := new(big.Int)
	zero.SetInt64(0)

	// Compute z, the first BitSize bits of hash(msg).
	//
	// NOTE(cjpatton) This part is definitely non-compliant; see hashToInt() in
	// https://golang.org/src/crypto/ecdsa/ecdsa.go.
	sk.hash.Reset()
	sk.hash.Write(msg)
	z.SetBytes(sk.hash.Sum(nil)[:sk.curve.Params().BitSize>>3])

	for {
		// Choose a random k in [0,N). (It should not be equal to 0, but this
		// occurs with negligible probability.)
		k, err := rand.Int(rand.Reader, sk.curve.Params().N)
		if err != nil {
			return nil, err
		}

		// Compute r.
		x1, _ = sk.curve.ScalarBaseMult(k.Bytes())
		r.Mod(x1, sk.curve.Params().N)
		if r.Cmp(zero) == 0 {
			continue
		}

		// Compute s.
		k.ModInverse(k, sk.curve.Params().N)
		s.Mul(r, sk.priv)
		s.Add(s, z)
		s.Mul(s, k)
		s.Mod(s, sk.curve.Params().N)
		if s.Cmp(zero) == 0 {
			continue
		}

		break
	}

	return asn1.Marshal(ecdsaSignature{r, s})
}

func (pk *PublicKey) Verify(msg, sig []byte) bool {
	return false
}
