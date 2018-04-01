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
	for i := 0; i < 1000; i++ {
		if g.PointAt(uint64(i)).IsValid() {
			t.Log(i)
		}
	}
	P := g.PointAt(934)
	Q := g.PointAt(961)
	t.Log(P.IsValid(), Q.IsValid(), Add(P, Q).IsValid())
}
