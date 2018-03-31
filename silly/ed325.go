package ed325

const (
	pBaseField = (1 << 32) - 5
	aBaseField = 2 // a square in GF(p)
	dBaseField = 3 // a non-square in GF(p)
)

func baseFieldInv0(x0, x, q uint64) uint64 {
	var y uint64
	y = (q * x) % pBaseField
	if x0 > y {
		y = x0 - y
	} else {
		y = x0 + pBaseField - y
	}
	return y % pBaseField
}

// Stolen from wikipedia
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
		r0, r = r, baseFieldInv0(r0, r, q)
		s0, s = s, baseFieldInv0(s0, s, q)
		t0, t = t, baseFieldInv0(t0, t, q)
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

// TODO Get rid of this after picking a point encoding.
// The only exported interface should be encoded points.
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
	return R
}

func Inv(P *Point) *Point {
	R := new(Point)
	return R
}

func ScalarMul(P *Point, x uint64) *Point {
	R := new(Point)
	return R
}
