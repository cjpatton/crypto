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

	if !curve.IsOnCurve(B.x, B.y) {
		close(ch)
		return nil, errors.New("client share is malformed")
	}

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

	// Get client share.
	A, ok := <-ch
	if !ok {
		return nil, errors.New("channel closed by peer")
	}

	if !curve.IsOnCurve(A.x, A.y) {
		close(ch)
		return nil, errors.New("client share is malformed")
	}

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
