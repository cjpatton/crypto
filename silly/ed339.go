package ed339

import (
	"math/big"
)

const (
	pBaseField = (1 << 33) - 9
	aBaseField = 1 // a square in GF(p)
	dBaseField = 5 // a non-square in GF(p)
)

func baseFieldSub(a, b uint64) uint64 {
	if a > b {
		a -= b
		a %= pBaseField
	} else {
		a += pBaseField - b
		a %= pBaseField
	}
	return a
}

func baseFieldMul(a, b uint64) uint64 {
	return (a * b) % pBaseField
}

func baseFieldMulInv(a uint64) uint64 {
	var s, t, r, s0, t0, r0 uint64
	s = 0
	t = 1
	r = pBaseField
	s0 = 1
	t0 = 0
	r0 = a
	for r != 0 {
		q := r0 / r
		r0, r = r, baseFieldSub(r0, baseFieldMul(q, r))
		s0, s = s, baseFieldSub(s0, baseFieldMul(q, s))
		t0, t = t, baseFieldSub(t0, baseFieldMul(q, t))
	}
	return s0
}

type Point struct {
	x, y uint64
	g    *Group
}

type Group struct {
	Order uint64
	Base  *Point
	Id    *Point
}

func New() *Group {
	g := new(Group)
	g.Order = 0              // TODO
	g.Base = &Point{0, 1, g} // TODO
	g.Id = &Point{0, 1, g}
	return g
}

func (g *Group) PointAt(y uint64) *Point {
	yy := baseFieldMul(y, y)
	u := baseFieldSub(1, yy)
	v := baseFieldSub(aBaseField, baseFieldMul(dBaseField, yy))
	xx := baseFieldMul(u, baseFieldMulInv(v))
	// TODO Do this without math/big.
	x := new(big.Int)
	p := new(big.Int)
	e := new(big.Int)
	x.SetUint64(xx)
	p.SetUint64(pBaseField)
	e.SetUint64((pBaseField + 1) / 4)
	x.Exp(x, e, p)
	return &Point{x.Uint64(), y, g}
}

func (P *Point) isOnCurve() bool {
	xx := baseFieldMul(P.x, P.x)
	yy := baseFieldMul(P.y, P.y)
	l := baseFieldMul(aBaseField, xx) + yy
	r := baseFieldMul(xx, yy)
	r = 1 + baseFieldMul(dBaseField, r)
	return (l % pBaseField) == (r % pBaseField)
}

func (P *Point) IsValid() bool {
	// TODO Check multiplication by group order gets the identity
	return P.isOnCurve()
}

func Add(P, Q *Point) *Point {
	R := new(Point)
	xs := baseFieldMul(P.x, Q.x)
	ys := baseFieldMul(P.y, Q.y)
	s := baseFieldMul(P.x, Q.y)
	t := baseFieldMul(P.y, Q.x)
	u := baseFieldMul(xs, ys)
	R.x = baseFieldMul(dBaseField, u)
	R.y = R.x
	R.x = baseFieldMulInv(R.x + 1)
	R.x = baseFieldMul(R.x, s+t)
	R.y = baseFieldSub(1, R.y)
	R.y = baseFieldMulInv(R.y)
	v := baseFieldMul(aBaseField, xs)
	v = baseFieldSub(ys, v)
	R.y = baseFieldMul(R.y, v)
	return R
}

func Inv(P *Point) *Point {
	return &Point{pBaseField - P.x, P.y, P.g}
}

func ScalarMul(P *Point, x uint64) *Point {
	R := new(Point)
	return R
}
