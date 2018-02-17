package ecdsa

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

func TestNewKeyPair(t *testing.T) {
	if _, _, err := NewKeyPair(elliptic.P256(), sha256.New()); err != nil {
		t.Error("NewKeyPair(P256, SHA512) fails:", err)
	}

	if _, _, err := NewKeyPair(elliptic.P521(), sha256.New()); err == nil {
		t.Error("NewKeyPair(P521, SHA256) passes, expected failure")
	}
}

func TestSignVerify(t *testing.T) {
	pk, sk, err := NewKeyPair(elliptic.P256(), sha512.New())
	if err != nil {
		t.Fatal("NewKeyPair() fails:", err)
	}

	msg := []byte("What a wonderful world.")

	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatal("Sign() fails:", err)
	}

	if ok, err := pk.Verify(msg, sig); err != nil {
		t.Fatal("Verify() fails:", err)
	} else if !ok {
		t.Error("Signature invalid: expected valid")
	}
}
