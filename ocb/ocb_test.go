package ocb

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func TestNewOCB(t *testing.T) {
	key := make([]byte, 16)
	aes, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	ocb := NewOCB(aes)

	lstar, _ := hex.DecodeString("66e94bd4ef8a2c3b884cfa59ca342b2e")
	if !bytes.Equal(ocb.lstar[:], lstar) {
		t.Errorf("lstar: got %v want %v", ocb.lstar, lstar)
	}

	ldollar, _ := hex.DecodeString("cdd297a9df1458771099f4b39468565c")
	if !bytes.Equal(ocb.ldollar[:], ldollar) {
		t.Errorf("ldollar: got %v want %v", ocb.ldollar, ldollar)
	}
}

var testOffsets = []string{
	"ee944b2fe6e9fc888042608da9615f75",
	"7531647c58c14c66a17189ea81b1f34a",
	"427b3adb24902dbae3165b24d010abb3",
	"d9de15889ab89d54c225b243f8c0078c",
	"b74aa8c6621a5eec46ea17df5b82b67e",
	"2cef8795dc32ee0267d9feb873521a41",
	"1ba5d932a0638fde25be2c7622f342b8",
	"8000f6611e4b3f30048dc5110a23ee87",
}

func TestInitializeOffset(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	aes, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	ocb := NewOCB(aes)

	var offset [16]byte
	expectedOffset, _ := hex.DecodeString(testOffsets[0])
	ocb.initializeOffset(&offset, nonce, 0)
	if !bytes.Equal(offset[:], expectedOffset) {
		t.Errorf("offset: got %x want %x", offset[:], expectedOffset)
	}
}

func TestNextOffset(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	aes, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	ocb := NewOCB(aes)

	var offset [16]byte
	ocb.initializeOffset(&offset, nonce, 0)
	for i := 1; i < len(testOffsets); i++ {
		expectedOffset, _ := hex.DecodeString(testOffsets[i])
		ocb.updateOffset(&offset, &offset)
		if !bytes.Equal(offset[:], expectedOffset) {
			t.Errorf("offset#%d: got %x want %x", i, offset[:], expectedOffset)
		}
	}
}

func TestOffsetFastForward(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	aes, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	var m, n, i uint32
	m = 3
	ocb := NewOCB(aes)

	for n = 2; n < m; n++ {
		// First, the normal way.
		var offset, offset2 [16]byte
		ocb.initializeOffset(&offset, nonce, 0)
		for i = 1; i < m; i++ {
			t.Logf("#%-4d %x", i, offset[:])
			ocb.updateOffset(&offset, &offset)
		}

		// Now, the "fast?" way.
		ocb.initializeOffset(&offset2, nonce, n)
		for i = 1; i < m-n; i++ {
			t.Logf("#%-4d %x", i, offset2[:])
			ocb.updateOffset(&offset2, &offset2)
		}

		if !bytes.Equal(offset[:], offset2[:]) {
			t.Errorf("offset#%d: got %x want %x", i, offset2[:], offset[:])
		}
	}

}
