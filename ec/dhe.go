package ec

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	h "hash"
	"math/big"
)

type DHShare struct {
	x, y *big.Int
}

func DoDHClient(curve elliptic.Curve, hash h.Hash, k int, ch chan *DHShare) ([]byte, error) {
	if hash.Size() < k {
		return nil, errors.New("hash output smaller than requested key length")
	}

	// Generate and send the client share.
	a, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	ch <- &DHShare{x, y}

	// Get server share.
	B, ok := <-ch
	if !ok {
		return nil, errors.New("channel closed by peer")
	}

	// TODO Check that B is on the curve.

	// Derive the key from the shared secret.
	x, y = curve.ScalarMult(B.x, B.y, a)
	hash.Reset()
	hash.Write(x.Bytes())
	hash.Write(y.Bytes())
	return hash.Sum(nil)[:k], nil
}

func DoDHServer(curve elliptic.Curve, hash h.Hash, k int, ch chan *DHShare) ([]byte, error) {
	if hash.Size() < k {
		return nil, errors.New("hash output smaller than requested key length")
	}

	// Getclient share.
	A, ok := <-ch
	if !ok {
		return nil, errors.New("channel closed by peer")
	}

	// TODO Check that A is on the curve.

	// Generate and send the server share.
	b, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	ch <- &DHShare{x, y}

	// Derive the key from the shared secret.
	x, y = curve.ScalarMult(A.x, A.y, b)
	hash.Reset()
	hash.Write(x.Bytes())
	hash.Write(y.Bytes())
	return hash.Sum(nil)[:k], nil
}
