package ed325

const (
	p = (1 << 32) - 5
	a = p - 1 // -1
	d = 3
)

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
	return &Point{x % p, y % p, g}
}

func (P *Point) isOnCurve() bool {
	xx := P.x * P.x
	xx %= p
	yy := P.y * P.y
	yy %= p
	l := a*xx + yy
	r := 1 + d*xx*yy
	return (l % p) == (r % p)
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
