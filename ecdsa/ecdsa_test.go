package ecdsa

import (
	"crypto/elliptic"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pk, sk, err := NewKeyPair(elliptic.P256())
	if err != nil {
		t.Fatal("NewKeyPair() fails:", err)
	}

	_ = pk
	_ = sk
}
