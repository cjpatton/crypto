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
	zero  *big.Int
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
	pk := &PublicKey{curve, hash, x, y, new(big.Int)}
	pk.zero.SetInt64(0)
	sk := &SecretKey{*pk, new(big.Int)}
	sk.priv.SetBytes(k)
	return pk, sk, nil
}

// NOTE(cjpatton) This part is definitely non-compliant; see hashToInt() in
// https://golang.org/src/crypto/ecdsa/ecdsa.go.
func msgToInt(msg []byte, hash h.Hash, n int) *big.Int {
	z := new(big.Int)
	hash.Reset()
	hash.Write(msg)
	z.SetBytes(hash.Sum(nil)[:n])
	return z
}

func (sk *SecretKey) Sign(msg []byte) ([]byte, error) {

	r := new(big.Int)
	s := new(big.Int)
	x1 := new(big.Int)

	z := msgToInt(msg, sk.hash, sk.curve.Params().BitSize>>3)

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
		if r.Cmp(sk.zero) == 0 {
			continue
		}

		// Compute s.
		k.ModInverse(k, sk.curve.Params().N)
		s.Mul(r, sk.priv)
		s.Add(s, z)
		s.Mul(s, k)
		s.Mod(s, sk.curve.Params().N)
		if s.Cmp(sk.zero) == 0 {
			continue
		}

		break
	}

	return asn1.Marshal(ecdsaSignature{r, s})
}

func (pk *PublicKey) Verify(msg, sig []byte) (bool, error) {
	if !pk.curve.IsOnCurve(pk.x, pk.y) {
		return false, errors.New("invalid public key")
	}

	// Parse the signature into r and s and check their ranges.
	esig := &ecdsaSignature{}
	if _, err := asn1.Unmarshal(sig, esig); err != nil {
		return false, err
	}

	if esig.R.Cmp(pk.zero) == 0 || esig.R.Cmp(pk.curve.Params().N) == 0 {
		return false, errors.New("r not in range")
	}

	if esig.S.Cmp(pk.zero) == 0 || esig.S.Cmp(pk.curve.Params().N) == 0 {
		return false, errors.New("s not in range")
	}

	return false, nil
}
