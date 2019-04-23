// Copyright (c) 2017, Christopher Patton. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package ltdf

import (
	"crypto/rand"
	"errors"
	//"fmt"
	"math/big"
)

// Params stores the public parameters for Diffie-Hellman or ElGamal
// encryption. These are a generator G and primes P and Q such that Q divides
// (P-1) and G^Q is congruent to 1 mod P; that is, <G> is a cyclic subgroup of
// Z/p of order Q.
type Params struct {
	P, Q, qMinusOne *big.Int
	G               []big.Int
}

// MaxMsgBytes returns the maximum number of message that may be encrypted
// under the modulus P.
func (params *Params) MaxMsgBytes() int {
	return (params.P.BitLen() / 8) - 4
}

// NewParamsFromStrings creates a Params object from strings encoding the
// parameters of the group in hexadecimal. Encryption is defined on
// integers between 0 and `msgCt`-1.
func NewParamsFromStrings(p, g, q string, msgCt int) *Params {
	params := new(Params)
	params.P = new(big.Int)
	params.Q = new(big.Int)
	params.G = make([]big.Int, msgCt)

	// Read 'P', the modulus
	if _, ok := params.P.SetString(p, 16); !ok {
		return nil
	}
	// Read 'Q', the order of the group.
	if _, ok := params.Q.SetString(q, 16); !ok {
		return nil
	}

	// Compute params.G[n] = G^n for each n from 0 to msgCt-1
	//
	// Set G^0
	params.G[0].SetUint64(1)

	// Read G^1, the generator
	if _, ok := params.G[1].SetString(g, 16); !ok {
		return nil
	}

	// Compute G^n for each integer [2, msgCt-1].
	for n := 2; n < msgCt; n++ {
		params.G[n].Mul(&params.G[n-1], &params.G[1])
	}

	params.qMinusOne = new(big.Int)
	params.qMinusOne.Sub(params.Q, &params.G[0])
	return params
}

// PublicKey stores the public key Y = G^X for Diffie-Hellman or ElGamal.
type PublicKey struct {
	Params
	Y []big.Int
}

// SecretKey stores the secret key X \in [1..Q-1] for Diffie-Hellman or ElGamal.
type SecretKey struct {
	Params
	X []big.Int
}

// GenerateKeys generates a vector of `n` public/private key pairs.
func (params *Params) GenerateKeys(n int) (pk *PublicKey, sk *SecretKey, err error) {
	sk = new(SecretKey)
	pk = new(PublicKey)
	sk.X = make([]big.Int, n)
	pk.Y = make([]big.Int, n)
	sk.Params = *params
	pk.Params = *params

	var r *big.Int
	for i := 0; i < n; i++ {
		// Choose a random secret key X.
		r, err = pk.Params.Sample()
		if err != nil {
			return nil, nil, err
		}
		sk.X[i] = *r

		// Compute Y = G^X mod P.
		pk.Y[i].Exp(&params.G[1], &sk.X[i], params.P)
	}
	return
}

// Sample returns a uniform-random value from [1..q-1].
func (params *Params) Sample() (*big.Int, error) {
	// Choose a random exponent in [0,Q-1).
	r, err := rand.Int(rand.Reader, params.qMinusOne)
	if err != nil {
		return nil, err
	}
	// Add 1 so that the exponent is in [1,Q-1].
	r.Add(r, &params.G[0])
	return r, nil
}

// Encrypt returns a homomorphic ElGamal ciphertext `(x, y)` under `pk.Y[i]`
// corresponding to `msg`, an element of the group, and `coins`, an integer in
// [1,q).
func (pk *PublicKey) Encrypt(i, msg int, coins *big.Int) (x *big.Int, y *big.Int, err error) {
	if msg < 0 || msg >= len(pk.Params.G) {
		return nil, nil, errors.New("message out of range")
	}
	if i < 0 || i >= len(pk.Y) {
		return nil, nil, errors.New("key index out of range")
	}
	err = nil
	var m *big.Int = &pk.Params.G[msg]
	x = new(big.Int)
	y = new(big.Int)
	x.Exp(&pk.Params.G[1], coins, pk.Params.P)
	y.Exp(&pk.Y[i], coins, pk.Params.P)
	y.Mul(y, m)
	return
}

// Decrypt returns the plaintext `msg`, an element of the group,  corresponding
// to the homorphic ElGamal ciphertext `(x, y)`.
func (sk *SecretKey) Decrypt(i int, x, y *big.Int) (msg int, err error) {
	if i < 0 || i >= len(sk.X) {
		return -1, errors.New("key index out of range")
	}
	m := new(big.Int).Exp(x, &sk.X[i], sk.Params.P)
	m.Div(y, m)
	err = errors.New("plaintext out of range")
	for idx := 0; idx < len(sk.Params.G); idx++ {
		if sk.Params.G[idx].Cmp(m) == 0 {
			msg = idx
			err = nil
		}
	}
	return
}
