package ecdsa

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
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

	var r, s, z, x1, zero *big.Int

	// Compute z, the first BitSize bits of hash(msg).
	z = new(big.Int)
	sk.hash.Reset()
	sk.hash.Write(msg)
	fmt.Println(z)
	z.SetBytes(sk.hash.Sum(nil)[:sk.curve.Params().BitSize>>3])

	zero = new(big.Int)
	zero.SetInt64(0)
	x1 = new(big.Int)
	r = new(big.Int)
	s = new(big.Int)

	for {
		// Choose a random k in [1,N).
		//
		// It's possible that k==0, but this occurs with negligible probability.
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

	return elliptic.Marshal(sk.curve, r, s), nil
}

func (pk *PublicKey) Verify(msg, sig []byte) bool {
	return false
}
