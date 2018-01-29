package ocb

import (
	"crypto/cipher"
	"fmt"
)

const (
	tagBytes  = 16
	tableSize = 32
)

type OCB struct {
	bc             cipher.Block
	blockCount     uint32
	ldollar, lstar [16]byte
	zeros          [16]byte
	l              [][16]byte
}

func NewOCB(bc cipher.Block) *OCB {
	if bc.BlockSize() != 16 {
		panic("The blockipher used for OCB must have a blocksize of 16 bytes.")
	}

	ocb := &OCB{bc: bc}
	bc.Encrypt(ocb.lstar[:], ocb.zeros[:])
	doubleBlock(&ocb.ldollar, &ocb.lstar)

	ocb.l = make([][16]byte, tableSize)
	copy(ocb.l[0][:], ocb.ldollar[:])
	for i := 1; i < tableSize; i++ {
		doubleBlock(&ocb.l[i], &ocb.l[i-1])
	}
	return ocb
}

func (ocb *OCB) initializeOffset(offset *[16]byte, n []byte, b uint32) {
	if len(n) > 15 {
		panic("The nonce must be at most 15 bytes in length.")
	}

	var nonce, ktop, tmp [16]byte
	var stretch [24]byte
	var bottom, byteshift, bitshift, i uint32
	copy(nonce[16-len(n):], n)
	nonce[0] = byte(((tagBytes * 8) % 128) << 1)
	nonce[16-len(n)-1] |= 0x01
	bottom = uint32(nonce[15] & 0x3F)
	nonce[15] &= 0xC0
	ocb.bc.Encrypt(ktop[:], nonce[:])
	copy(stretch[:], ktop[:])
	copy(tmp[:], ktop[1:9])
	xorBlock(&tmp, &tmp, &ktop)
	copy(stretch[16:], tmp[8:])
	byteshift = bottom / 8
	bitshift = bottom % 8
	if bitshift != 0 {
		for i = 0; i < 16; i++ {
			offset[i] = (stretch[i+byteshift] << bitshift) |
				(stretch[i+byteshift+1] >> (8 - bitshift))
		}
	} else {
		for i = 0; i < 16; i++ {
			offset[i] = stretch[i+byteshift]
		}
	}

	ocb.blockCount = b
	ocb.addDelta(offset, offset, b)
}

var tzTable = []uint32{
	0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
	31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9,
}

func ntz(x uint32) uint32 {
	// Compute ntz(i).
	// This method was taken from Ted Krovetz' optimized implemntation:
	// web.cs.ucdavis.edu/~rogaway/ocb/news/code/ocb.c
	return tzTable[(uint32((x&-x)*uint32(0x077CB531)))>>27]
}

func (ocb *OCB) updateOffset(dst, src *[16]byte) {
	ocb.blockCount++
	xorBlock(dst, src, &ocb.l[ntz(ocb.blockCount)+1])
}

func xorBlock(dst, src1, src2 *[16]byte) {
	for i := 0; i < 16; i++ {
		dst[i] = src1[i] ^ src2[i]
	}
}

func doubleBlock(dst, src *[16]byte) {
	tmp := src[0]
	for i := 0; i < 15; i++ {
		dst[i] = (src[i] << 1) | (src[i+1] >> 7)
	}
	dst[15] = (src[15] << 1) ^ ((tmp >> 7) * 135)
}

func binToGray(x uint32) uint32 {
	return x ^ (x >> 1)
}

func (ocb *OCB) addDelta(dst, src *[16]byte, i uint32) {
	// TODO Replace this slow code with something faster.
	var j uint32
	for j = 0; j < i; j++ {
		xorBlock(dst, src, &ocb.l[ntz(j+1)+1])
	}

	// dst = Deltia
	// src = Initial
	// lstar = L
	a := binToGray(i)
	lambda := 4 * a
	// TODO Multiply lstar by lambda and reduce it mod x^128 + x^7 + x^2 + x + 1
	// (as in Sec. 4.3 http://web.cs.ucdavis.edu/~rogaway/papers/ae.pdf)).
}
