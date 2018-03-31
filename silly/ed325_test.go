package ed325

import (
	"math/big"
	"testing"
)

func TestIsOnCurve(t *testing.T) {
	g := New()
	t.Log(g.NewPoint(132, 43).IsValid())
	t.Log(g.Id.IsValid())
}

func TestModularInverse(t *testing.T) {
	b := uint64(43)
	y := baseFieldInv(b)

	a := new(big.Int)
	p := new(big.Int)
	x := new(big.Int)
	a.SetUint64(b)
	p.SetUint64(pBaseField)
	x.ModInverse(a, p)

	if y != x.Uint64() {
		t.Errorf("baseFieldInv(23): got %d, expected %d", y, x.Uint64())
	}
}

func TestAdd(t *testing.T) {
	g := New()
	P := g.NewPoint(234, 3)
	t.Log(Add(g.Id, g.Id))
}
