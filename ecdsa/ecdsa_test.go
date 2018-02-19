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

	for i := 0; i < 100; i++ {
		sig, err := sk.Sign(msg)
		if err != nil {
			t.Fatal("Sign() fails:", err)
		}

		// Valid signature.
		if ok, err := pk.Verify(msg, sig); err != nil {
			t.Fatal("Verify(good sig) fails:", err)
		} else if !ok {
			t.Error("Signature invalid: expected valid")
		}

		// Mangled signature.
		sig[0] ^= 0xff
		if _, err := pk.Verify(msg, sig); err == nil {
			t.Error("Verify(mangled sig) passes, expected error")
		}

		// Invalid singature.
		sig[0] ^= 0xff
		msg[0] = byte(i)
		if ok, err := pk.Verify(msg, sig); err != nil {
			t.Fatal("Verify(invalid sig) fails:", err)
		} else if ok {
			t.Error("Signature valid: expected invalid")
		}
	}
}
