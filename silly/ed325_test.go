package ed325

import "testing"

func TestIsOnCurve(t *testing.T) {
	g := New()
	t.Log(g.NewPoint(132, 43).IsValid())
	t.Log(g.Id.IsValid())
}
