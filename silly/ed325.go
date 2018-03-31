package ed325

const (
	pBaseField = (1 << 32) - 5
	aBaseField = 2 // a square in GF(p)
	dBaseField = 3 // a non-square in GF(p)
)

// Should be constant time.
func baseFieldSub(a, b uint64) uint64 {
	if a > b {
		a -= b
	} else {
		a += pBaseField - b
	}
	return a % pBaseField
}

// Should be constant time.
func baseFieldInv(a uint64) uint64 {
	var s, t, r, s0, t0, r0 uint64
	s = 0
	t = 1
	r = pBaseField
	s0 = 1
	t0 = 0
	r0 = a
	for r != 0 {
		q := r0 / r
		r0, r = r, baseFieldSub(r0, (q*r)%pBaseField)
		s0, s = s, baseFieldSub(s0, (q*s)%pBaseField)
		t0, t = t, baseFieldSub(t0, (q*t)%pBaseField)
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

// TODO compute x from y.
func (g *Group) NewPoint(x, y uint64) *Point {
	return &Point{x % pBaseField, y % pBaseField, g}
}

func (P *Point) isOnCurve() bool {
	xx := P.x * P.x
	xx %= pBaseField
	yy := P.y * P.y
	yy %= pBaseField
	l := aBaseField*xx + yy
	r := xx * yy
	r %= pBaseField
	r = 1 + dBaseField*r
	return (l % pBaseField) == (r % pBaseField)
}

func (P *Point) IsValid() bool {
	// TODO Check multiplication by group order gets the identity
	return P.isOnCurve()
}

func Add(P, Q *Point) *Point {
	R := new(Point)

	xs := P.x * Q.x
	xs %= pBaseField
	ys := P.y * Q.y
	ys %= pBaseField

	u := xs * ys
	u %= pBaseField

	s := P.x * Q.y
	s %= pBaseField

	t := P.y * Q.x
	t %= pBaseField

	R.x = dBaseField * u
	R.x %= pBaseField
	R.y = R.x
	R.x = baseFieldInv(R.x + 1)
	R.x *= s + t
	R.x %= pBaseField

	R.y = baseFieldSub(1, R.y)
	R.y = baseFieldInv(R.y)
	v := xs * aBaseField
	v %= pBaseField
	v = baseFieldSub(ys, v)
	R.y *= v
	R.y %= pBaseField

	return R
}

func Inv(P *Point) *Point {
	return &Point{-P.x, P.y, P.g}
}

func ScalarMul(P *Point, x uint64) *Point {
	R := new(Point)
	return R
}
