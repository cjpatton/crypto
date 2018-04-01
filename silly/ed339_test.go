package ed339

import (
	"math/big"
	"testing"
)

func TestIsOnCurve(t *testing.T) {
	g := New()
	t.Log(g.PointAt(4).IsValid())
	t.Log(g.Id.IsValid())
}

func TestModularInverse(t *testing.T) {
	b := uint64(43)
	y := baseFieldMulInv(b)

	a := new(big.Int)
	p := new(big.Int)
	x := new(big.Int)
	a.SetUint64(b)
	p.SetUint64(pBaseField)
	x.ModInverse(a, p)

	if y != x.Uint64() {
		t.Errorf("baseFieldMulInv(23): got %d, expected %d", y, x.Uint64())
	}
}

func TestAdd(t *testing.T) {
	g := New()
	P := g.PointAt(234324)
	t.Log(P.IsValid())
}
