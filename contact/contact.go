package main

import (
	"crypto/rand"
	"fmt"
	bn "golang.org/x/crypto/bn256"
)

func main() {
	// This implements the tripartite Diffie-Hellman algorithm from "A One
	// Round Protocol for Tripartite Diffie-Hellman", A. Joux.
	// http://www.springerlink.com/content/cddc57yyva0hburb/fulltext.pdf

	// Each of three parties, a, b and c, generate a private value.
	a, _ := rand.Int(rand.Reader, bn.Order)
	b, _ := rand.Int(rand.Reader, bn.Order)
	c, _ := rand.Int(rand.Reader, bn.Order)

	// Then each party calculates g₁ and g₂ times their private value.
	pa := new(bn.G1).ScalarBaseMult(a)
	qa := new(bn.G2).ScalarBaseMult(a)

	pb := new(bn.G1).ScalarBaseMult(b)
	qb := new(bn.G2).ScalarBaseMult(b)

	pc := new(bn.G1).ScalarBaseMult(c)
	qc := new(bn.G2).ScalarBaseMult(c)

	// Now each party exchanges its public values with the other two and
	// all parties can calculate the shared key.
	k1 := bn.Pair(pb, qc)
	k1.ScalarMult(k1, a)

	k2 := bn.Pair(pc, qa)
	k2.ScalarMult(k2, b)

	k3 := bn.Pair(pa, qb)
	k3.ScalarMult(k3, c)

	// k1, k2 and k3 will all be equal.
	fmt.Println(pb)
	fmt.Println(qc)
	fmt.Println(k1)
}
