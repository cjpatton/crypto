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
	x, y  big.Int
	st    [4]big.Int
}

type SecretKey struct {
	PublicKey
	priv big.Int
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
	pk := &PublicKey{curve: curve, hash: hash, x: *x, y: *y}
	pk.st[0].SetInt64(0)
	sk := &SecretKey{*pk, big.Int{}}
	sk.priv.SetBytes(k)
	return pk, sk, nil
}

func (sk *SecretKey) Sign(msg []byte) ([]byte, error) {

	zero := &sk.st[0]
	r := &sk.st[1]
	s := &sk.st[2]
	x1 := &sk.st[3]

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
		if r.Cmp(zero) == 0 {
			continue
		}

		// Compute s.
		k.ModInverse(k, sk.curve.Params().N)
		s.Mul(r, &sk.priv)
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

func (pk *PublicKey) Verify(msg, sig []byte) (bool, error) {

	zero := &pk.st[0]
	w := &pk.st[1]
	u1 := &pk.st[2]
	u2 := &pk.st[3]

	// Check that the public key is valid.
	if !pk.curve.IsOnCurve(&pk.x, &pk.y) {
		return false, errors.New("invalid public key")
	}

	// Parse the signature into r and s and check that they are in range.
	esig := &ecdsaSignature{}
	if _, err := asn1.Unmarshal(sig, esig); err != nil {
		return false, err
	}

	if esig.R.Cmp(zero) == 0 || esig.R.Cmp(pk.curve.Params().N) == 0 {
		return false, errors.New("r not in range")
	}

	if esig.S.Cmp(zero) == 0 || esig.S.Cmp(pk.curve.Params().N) == 0 {
		return false, errors.New("s not in range")
	}

	z := msgToInt(msg, pk.hash, pk.curve.Params().BitSize>>3)
	w.ModInverse(esig.S, pk.curve.Params().N)
	u1.Mul(z, w)
	//u1.Mod(u1, pk.curve.Params().N)
	u2.Mul(esig.R, w)
	//u2.Mod(u2, pk.curve.Params().N)
	a1, b1 := pk.curve.ScalarBaseMult(u1.Bytes())
	a2, b2 := pk.curve.ScalarMult(&pk.x, &pk.y, u2.Bytes())
	x1, y1 := pk.curve.Add(a1, b1, a2, b2)
	x1.Mod(x1, pk.curve.Params().N)
	y1.Mod(y1, pk.curve.Params().N)
	if (x1.Cmp(zero) == 0 && y1.Cmp(zero) == 0) || x1.Cmp(esig.R) != 0 {
		return false, nil
	}
	return true, nil
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
