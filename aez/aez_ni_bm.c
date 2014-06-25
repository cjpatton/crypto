// AEZ v1.0d1 optimized AES-NI code. Currently under development.
//
// Written by Ted Krovetz (ted@krovetz.net). Last modified 21 March 2014.
//
// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
#include <stdint.h>
#include <wmmintrin.h>
#include <tmmintrin.h>

#define ALIGN(n) __attribute__ ((aligned(n)))

typedef unsigned char byte;

typedef struct {
    __m128i aes_key[11];
    __m128i aesinv_key[11];
    __m128i J;              // 2J             (register correct)
    __m128i Itab[3];        // I, 2I, 4I      (memory correct)
    __m128i Ltab[4];        // L, 2L, 4L, 8L  (memory correct)
} aez_key_t;

#include <stdio.h>
void pbuf(byte *p, int len, char *s)
{
    if (s) printf("%s", s);
    for (int i = 0; i < len; i++)
        printf("%02X", (unsigned)(((unsigned char *)p)[i]));
    printf("\n");
}

/* ------------------------------------------------------------------------- */

#define SETUP_STEP(v1,v2,v3,shuff_const,aes_const)                       \
    v2 = _mm_aeskeygenassist_si128(v1,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2)

static void aes_setup(__m128i key, __m128i *rk) {
    __m128i x0=key, x1, x2=_mm_setzero_si128();
                                  rk[0]  = x0;
    SETUP_STEP(x0,x1,x2,255,1);   rk[1]  = x0;
    SETUP_STEP(x0,x1,x2,255,2);   rk[2]  = x0;
    SETUP_STEP(x0,x1,x2,255,4);   rk[3]  = x0;
    SETUP_STEP(x0,x1,x2,255,8);   rk[4]  = x0;
    SETUP_STEP(x0,x1,x2,255,16);  rk[5]  = x0;
    SETUP_STEP(x0,x1,x2,255,32);  rk[6]  = x0;
    SETUP_STEP(x0,x1,x2,255,64);  rk[7]  = x0;
    SETUP_STEP(x0,x1,x2,255,128); rk[8]  = x0;
    SETUP_STEP(x0,x1,x2,255,27);  rk[9]  = x0;
    SETUP_STEP(x0,x1,x2,255,54);  rk[10] = x0;
}

static __m128i aes(__m128i key[11], __m128i offset, __m128i in) {
	in = _mm_aesenc_si128 (in^key[0]^offset,key[1]);
	in = _mm_aesenc_si128 (in,key[2]);
	in = _mm_aesenc_si128 (in,key[3]);
	in = _mm_aesenc_si128 (in,key[4]);
	in = _mm_aesenc_si128 (in,key[5]);
	in = _mm_aesenc_si128 (in,key[6]);
	in = _mm_aesenc_si128 (in,key[7]);
	in = _mm_aesenc_si128 (in,key[8]);
	in = _mm_aesenc_si128 (in,key[9]);
	return _mm_aesenclast_si128 (in,key[10]^offset);
}

static __m128i aesinv(__m128i key[11], __m128i offset, __m128i in) {
	in = _mm_aesdec_si128 (in^key[0]^offset,key[1]);
	in = _mm_aesdec_si128 (in,key[2]);
	in = _mm_aesdec_si128 (in,key[3]);
	in = _mm_aesdec_si128 (in,key[4]);
	in = _mm_aesdec_si128 (in,key[5]);
	in = _mm_aesdec_si128 (in,key[6]);
	in = _mm_aesdec_si128 (in,key[7]);
	in = _mm_aesdec_si128 (in,key[8]);
	in = _mm_aesdec_si128 (in,key[9]);
	return _mm_aesdeclast_si128 (in,key[10]^offset);
}

static __m128i aes4(__m128i key[11], __m128i offset, __m128i in) {
	in = _mm_aesenc_si128 (in^offset,key[2]);
	in = _mm_aesenc_si128 (in,key[5]);
	in = _mm_aesenc_si128 (in,key[8]);
	return _mm_aesenclast_si128 (in,_mm_setzero_si128());
}

/* ------------------------------------------------------------------------- */

static __m128i bswap16(__m128i b) {
  return _mm_shuffle_epi8(b,_mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15));
}

static __m128i double_block(__m128i bl) {
    const __m128i mask = _mm_set_epi32(135,1,1,1);
    __m128i tmp = _mm_srai_epi32(bl, 31);
    tmp = _mm_and_si128(tmp, mask);
    tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));
    bl = _mm_slli_epi32(bl, 1);
    return _mm_xor_si128(bl,tmp);
}

/* ------------------------------------------------------------------------- */

void aez_key_setup(__m128i key, aez_key_t *aez_key) {
    __m128i tmp;
    ALIGN(16) byte one[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    ALIGN(16) byte two[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
    aes_setup(key, aez_key->aes_key);
    aez_key->aesinv_key[0] = aez_key->aes_key[10];
    aez_key->aesinv_key[1] = _mm_aesimc_si128(aez_key->aes_key[9]);
    aez_key->aesinv_key[2] = _mm_aesimc_si128(aez_key->aes_key[8]);
    aez_key->aesinv_key[3] = _mm_aesimc_si128(aez_key->aes_key[7]);
    aez_key->aesinv_key[4] = _mm_aesimc_si128(aez_key->aes_key[6]);
    aez_key->aesinv_key[5] = _mm_aesimc_si128(aez_key->aes_key[5]);
    aez_key->aesinv_key[6] = _mm_aesimc_si128(aez_key->aes_key[4]);
    aez_key->aesinv_key[7] = _mm_aesimc_si128(aez_key->aes_key[3]);
    aez_key->aesinv_key[8] = _mm_aesimc_si128(aez_key->aes_key[2]);
    aez_key->aesinv_key[9] = _mm_aesimc_si128(aez_key->aes_key[1]);
    aez_key->aesinv_key[10] = aez_key->aes_key[0];
    tmp = aes(aez_key->aes_key, _mm_setzero_si128(), _mm_setzero_si128());
    aez_key->Itab[0] = tmp; tmp = bswap16(tmp);
    aez_key->Itab[1] = bswap16(tmp = double_block(tmp));
    aez_key->Itab[2] = bswap16(double_block(tmp));
    tmp = aes(aez_key->aes_key, _mm_setzero_si128(), *(__m128i*)one);
    aez_key->J = double_block(bswap16(tmp));
    tmp = aes(aez_key->aes_key, _mm_setzero_si128(), *(__m128i*)two);
    aez_key->Ltab[0] = tmp; tmp = bswap16(tmp);
    aez_key->Ltab[1] = bswap16(tmp = double_block(tmp));
    aez_key->Ltab[2] = bswap16(tmp = double_block(tmp));
    aez_key->Ltab[3] = bswap16(double_block(tmp));
}

/* ------------------------------------------------------------------------- */

__m128i load_and_10pad(byte *p, int bytes) {
    ALIGN(16) byte buf[16];
    *(__m128i*)buf = _mm_setzero_si128();
    for (int i=0; i<bytes; i++) buf[i]=p[i];
    buf[bytes]=0x80;
    return *(__m128i*)buf;
}

__m128i aez_extract_key(byte *user_key, int numbytes) {
    ALIGN(16) byte CONST1[] = {0xc2, 0x4a, 0x39, 0xcb, 0x65, 0x8a, 0x00, 0x78,
                               0x32, 0x10, 0x3d, 0x01, 0x70, 0x41, 0xd6, 0xa4},
                   CONST2[] = {0x2d, 0x11, 0xd7, 0xfb, 0x36, 0x74, 0xc7, 0xfd,
                               0xa5, 0x15, 0xed, 0xbe, 0x4d, 0xff, 0x50, 0x5e},
                   CONST3[] = {0x5f, 0xa8, 0xe0, 0xaa, 0xf9, 0x83, 0x1f, 0x4a,
                               0x0b, 0x00, 0x7c, 0x5d, 0x04, 0xa0, 0x02, 0xf0},
                   CONST4[] = {0xd0, 0x93, 0xa0, 0xa9, 0xcd, 0x8d, 0xc1, 0x13,
                               0x79, 0x4f, 0x32, 0x93, 0x0d, 0xeb, 0x58, 0x6c};
    if (numbytes == 16)
        return _mm_loadu_si128((__m128i*)user_key) ^ *(__m128i*)CONST1;
    else {
        __m128i key[11], res = _mm_setzero_si128();
        aes_setup(*(__m128i*)CONST4, key);
        for ( ; numbytes > 16; numbytes-=16, user_key+=16)
            res = aes(key, _mm_setzero_si128(), res ^ _mm_loadu_si128((__m128i*)user_key));
        if (numbytes==16)
            return aes(key, _mm_setzero_si128(), res ^ _mm_loadu_si128((__m128i*)user_key) ^ *(__m128i*)CONST2);
        else {
            __m128i tmp = load_and_10pad(user_key, numbytes);
            return aes(key, _mm_setzero_si128(), res ^ tmp ^ *(__m128i*)CONST3);
        }
    }
}

/* ------------------------------------------------------------------------- */

__m128i AHash(aez_key_t *aez_key, int abytes, __m128i *m, unsigned mbytes)
{
    unsigned i;
    __m128i sigma = _mm_setzero_si128(), J = aez_key->J;
    __m128i k0 = bswap16(J), k1, k2, k3, buf[9];
    while (mbytes >= 128) {
        J = double_block(J);
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        sigma ^= aes4(aez_key->aes_key, k0, m[0]);
        sigma ^= aes4(aez_key->aes_key, k1, m[1]);
        sigma ^= aes4(aez_key->aes_key, k2, m[2]);
        sigma ^= aes4(aez_key->aes_key, k3, m[3]);
        sigma ^= aes4(aez_key->aes_key, k0^aez_key->Itab[2], m[4]);
        sigma ^= aes4(aez_key->aes_key, k1^aez_key->Itab[2], m[5]);
        sigma ^= aes4(aez_key->aes_key, k2^aez_key->Itab[2], m[6]);
        sigma ^= aes4(aez_key->aes_key, k3^aez_key->Itab[2], m[7]);
        k0 = bswap16(J); m+=8; mbytes-=128;
    }
    if (abytes) {
        for (i=0; i*16 < mbytes; i++)                  buf[i] = m[i];
        for (i=mbytes; i<mbytes+abytes; i++) ((byte *)buf)[i] = 0;
        if (i%16) {
            ((byte *)buf)[i++]=0x80;
            for ( ; i%16; i++)                   ((byte *)buf)[i] = 0;
        }
        m = buf;
        mbytes = i;
    }
    if (mbytes >= 128) {
        J = double_block(J);
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        sigma ^= aes4(aez_key->aes_key, k0, m[0]);
        sigma ^= aes4(aez_key->aes_key, k1, m[1]);
        sigma ^= aes4(aez_key->aes_key, k2, m[2]);
        sigma ^= aes4(aez_key->aes_key, k3, m[3]);
        sigma ^= aes4(aez_key->aes_key, k0^aez_key->Itab[2], m[4]);
        sigma ^= aes4(aez_key->aes_key, k1^aez_key->Itab[2], m[5]);
        sigma ^= aes4(aez_key->aes_key, k2^aez_key->Itab[2], m[6]);
        sigma ^= aes4(aez_key->aes_key, k3^aez_key->Itab[2], m[7]);
        k0 = bswap16(J); m+=8; mbytes-=128;
    }
    if (mbytes >= 64) {
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        sigma ^= aes4(aez_key->aes_key, k0, m[0]);
        sigma ^= aes4(aez_key->aes_key, k1, m[1]);
        sigma ^= aes4(aez_key->aes_key, k2, m[2]);
        sigma ^= aes4(aez_key->aes_key, k3, m[3]);
        k0 = k0^aez_key->Itab[2]; m+=4; mbytes-=64;
    }
    if (mbytes >= 32) {
        k1 = k0^aez_key->Itab[0];
        sigma ^= aes4(aez_key->aes_key, k0, m[0]);
        sigma ^= aes4(aez_key->aes_key, k1, m[1]);
        k0 = k0^aez_key->Itab[1]; m+=2; mbytes-=32;
    }
    if (mbytes >= 16) {
        sigma ^= aes4(aez_key->aes_key, k0, m[0]);
        k0 = k0^aez_key->Itab[0]; m+=1; mbytes-=16;
    }
    if (mbytes%16) {
        sigma ^= aes4(aez_key->aes_key, k0, load_and_10pad((byte*)m, mbytes));
    }
    return sigma;
}

__m128i AMAC(aez_key_t *aez_key, __m128i offset, byte *first, byte *rest, int numbytes) {
    if (numbytes < 16) {
        return aes(aez_key->aes_key, offset, load_and_10pad(first, numbytes));
    } else {
        __m128i sigma;
        if (numbytes > 16) sigma = AHash(aez_key, 0, (__m128i*)rest, numbytes-16);
        else               sigma = _mm_setzero_si128();
        return aes(aez_key->aes_key, offset, sigma ^ *(__m128i*)first);
    }
}

__m128i AMAC_tweak(aez_key_t *aez_key, __m128i offset, int abytes, byte *n, int nbytes, byte *ad, int adbytes) {
// Possibly unsafe reads of n, if n is < 16 bytes before a page boundary
    ALIGN(16) byte first[20];
    if (nbytes == 12) {
        _mm_storeu_si128((__m128i*)(first+4),_mm_loadu_si128((__m128i*)n));
        *(uint32_t*)first = 0x40 + abytes;  // LE write: (info:00:00:00)
    } else if (nbytes < 12) {
        if (nbytes) _mm_storeu_si128((__m128i*)(first+4),_mm_loadu_si128((__m128i*)n));
        *(uint32_t*)first = abytes;         // LE write: (info:00:00:00)
        first[nbytes+4] = 0x80;
        for (int i=nbytes+5; i<16; i++) first[i]=0;
    } else {
        // Nonces greater than 12 not yet supported
    }
    __m128i tmp = *(__m128i*)first;
    if (adbytes) tmp ^= AHash(aez_key, 0, (__m128i*)ad, adbytes);
    return aes(aez_key->aes_key, offset, tmp);
}

/* ------------------------------------------------------------------------- */

static void complement_if_needed(byte *Delta, int numbytes, byte *src, byte *dst) {
    int i;
    byte comp[16], and=0xff, or=0x00;
    for (i=0; i<numbytes; i++) { and &= src[i]; or |= src[i]; comp[i] = ~src[i]; }
    int delta_bit = ( Delta[(numbytes-1)/8] >> ((16-numbytes)%8) ) & 1;
    if ( (delta_bit + (and==0xff) + (or==0x00)) == 2 )
         for (i=0; i<numbytes; i++) dst[i]=comp[i];
    else for (i=0; i<numbytes; i++) dst[i]=src[i];
}

void aez_encipher_ff0(aez_key_t *aez_key, int abytes, byte *n, int nbytes, byte *ad,
                    int adbytes, byte *m, int mbytes, byte *c) {
    int i,k;
    ALIGN(16) byte buf_in[16];
    ALIGN(16) byte buf_out[16];
    __m128i offset, tmp;
    if (adbytes%16) offset = aez_key->Ltab[3] ^ aez_key->Ltab[1] ^ aez_key->Ltab[0];
    else            offset = aez_key->Ltab[2] ^ aez_key->Ltab[1];
    __m128i delta = AMAC_tweak(aez_key, offset, abytes, n, nbytes, ad, adbytes);

    uint64_t A,B,mask1,mask2;
    A = *(uint64_t *)m;
	B = __builtin_bswap64(A) << (mbytes*4);
    if (mbytes > 8)  B |= __builtin_bswap64(*(uint64_t *)(m+8)) >> (64-mbytes*4);
    B = __builtin_bswap64(B);

    if (mbytes&1) {
        mask1 = ((uint64_t)(0xf0ffffffffffffffull)) >> (60-mbytes*4);
        mask2 = (uint64_t)0x08 << (mbytes/2*8);
    } else {
    	mask1 = ((uint64_t)(-1)) >> (64-mbytes*4);
    	mask2 = (uint64_t)0x80 << (mbytes*4);
    }
    
    if (mbytes <= 2) { if (mbytes==2) k=16; else k=24; } else k=10;

	*(__m128i *)buf_in = _mm_setzero_si128();
	for (i=1; i<=k; i+=2) {
		buf_in[3] = i;
		*(uint64_t *)(buf_in+4) = (B & mask1) | mask2;
		tmp = aes4(aez_key->aes_key, aez_key->Ltab[1], delta ^ *(__m128i *)buf_in);
        A ^= _mm_cvtsi128_si64(tmp);
        
		buf_in[3] = i+1;
		*(uint64_t *)(buf_in+4) = (A & mask1) | mask2;
		tmp = aes4(aez_key->aes_key, aez_key->Ltab[1], delta ^ *(__m128i *)buf_in);
        B ^= _mm_cvtsi128_si64(tmp);
	}
	
    A = __builtin_bswap64(A & mask1);
    B = __builtin_bswap64(B & mask1);
    //int pop = __builtin_popcountll(A) + __builtin_popcountll(B);
    //int delta_bit = ( Delta[(numbytes-1)/8] >> ((16-numbytes)%8) ) & 1;

    A |= (B >> (mbytes*4));
    B <<= (64-mbytes*4);
    *(uint64_t *)buf_out = __builtin_bswap64(A);
    *(uint64_t *)(buf_out+8) = __builtin_bswap64(B);
    complement_if_needed((byte *)&delta, mbytes, buf_out, c);
}

/* ------------------------------------------------------------------------- */

void aez_encipher_mem_16_multiple(aez_key_t * restrict aez_key, __m128i delta, int abytes, __m128i * restrict m, int mbytes, __m128i * restrict c) {
    int i;
    __m128i offset, tmp, X0, Y0;
    __m128i sigma = _mm_setzero_si128(), J = aez_key->J;
    __m128i k0 = bswap16(J), k1, k2, k3, buf[9];
    __m128i *m_orig=m, *c_orig=c;
    
    tmp = AHash(aez_key, abytes, m+1, mbytes-16);
    offset = aez_key->Ltab[2] ^ aez_key->Ltab[0];
    X0 = aes(aez_key->aes_key, offset, delta ^ tmp ^ *m);
    Y0 = aes(aez_key->aes_key, aez_key->Ltab[0], X0);

    m++; c++; mbytes-=16;
    while (mbytes >= 128) {
        J = double_block(J);
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        c[0] = tmp = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, tmp);
        c[1] = tmp = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, tmp);
        c[2] = tmp = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[2]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, tmp);
        c[3] = tmp = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[3]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, tmp);
        k0 ^= aez_key->Itab[2]; k1 ^= aez_key->Itab[2]; k2 ^= aez_key->Itab[2]; k3 ^= aez_key->Itab[2];
        c[4] = tmp = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[4]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, tmp);
        c[5] = tmp = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[5]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, tmp);
        c[6] = tmp = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[6]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, tmp);
        c[7] = tmp = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[7]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, tmp);
        k0 = bswap16(J); m+=8; c+=8; mbytes-=128;
    }
    if (abytes) {
        for (i=0; i*16 < mbytes; i++)                  buf[i] = m[i];
        for (i=mbytes; i<mbytes+abytes; i++) ((byte *)buf)[i] = 0;
        m = buf;
        mbytes = i;
    }
    if (mbytes >= 128) {
        J = double_block(J);
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        c[1] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[1]);
        c[2] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[2]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[2]);
        c[3] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[3]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[3]);
        k0 ^= aez_key->Itab[2]; k1 ^= aez_key->Itab[2]; k2 ^= aez_key->Itab[2]; k3 ^= aez_key->Itab[2];
        c[4] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[4]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[4]);
        c[5] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[5]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[5]);
        c[6] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[6]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[6]);
        c[7] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[7]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[7]);
        k0 = bswap16(J); m+=8; c+=8; mbytes-=128;
    }
    if (mbytes >= 64) {
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        c[1] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[1]);
        c[2] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[2]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[2]);
        c[3] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[3]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[3]);
        k0 = k0^aez_key->Itab[2]; m+=4; c+=4; mbytes-=64;
    }
    if (mbytes >= 32) {
        k1 = k0^aez_key->Itab[0];
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        c[1] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[1]);
        k0 = k0^aez_key->Itab[1]; m+=2; c+=2; mbytes-=32;
    }
    if (mbytes >= 16) {
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
    }
    *c_orig = delta ^ sigma ^ aesinv(aez_key->aesinv_key, offset, Y0);
}

void aez_encipher_mem_16_multiple_x(aez_key_t * restrict aez_key, __m128i delta, int abytes, __m128i * restrict m, int mbytes, __m128i * restrict c) {
    int i;
    __m128i offset, tmp, X0, Y0;
    __m128i sigma = _mm_setzero_si128(), J = aez_key->J;
    __m128i k0 = bswap16(J), k1, k2, k3, buf[9];
    __m128i *m_orig=m, *c_orig=c;
    
    tmp = AHash(aez_key, abytes, m+1, mbytes-16);
    offset = aez_key->Ltab[2] ^ aez_key->Ltab[0];
    X0 = aes(aez_key->aes_key, offset, delta ^ tmp ^ *m);
    Y0 = aes(aez_key->aes_key, aez_key->Ltab[0], X0);

    m++; c++; mbytes-=16;
    while (mbytes >= 128) {
        J = double_block(J);
        __m128i pre1 = 
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        c[1] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[1]);
        c[2] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[2]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[2]);
        c[3] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[3]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[3]);
        k0 ^= aez_key->Itab[2]; k1 ^= aez_key->Itab[2]; k2 ^= aez_key->Itab[2]; k3 ^= aez_key->Itab[2];
        c[4] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[4]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[4]);
        c[5] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[5]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[5]);
        c[6] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[6]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[6]);
        c[7] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[7]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[7]);
        k0 = bswap16(J); m+=8; c+=8; mbytes-=128;
    }
    if (abytes) {
        for (i=0; i*16 < mbytes; i++)                  buf[i] = m[i];
        for (i=mbytes; i<mbytes+abytes; i++) ((byte *)buf)[i] = 0;
        m = buf;
        mbytes = i;
    }
    if (mbytes >= 128) {
        J = double_block(J);
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        c[1] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[1]);
        c[2] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[2]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[2]);
        c[3] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[3]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[3]);
        k0 ^= aez_key->Itab[2]; k1 ^= aez_key->Itab[2]; k2 ^= aez_key->Itab[2]; k3 ^= aez_key->Itab[2];
        c[4] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[4]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[4]);
        c[5] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[5]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[5]);
        c[6] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[6]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[6]);
        c[7] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[7]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[7]);
        k0 = bswap16(J); m+=8; c+=8; mbytes-=128;
    }
    if (mbytes >= 64) {
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        c[1] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[1]);
        c[2] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[2]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[2]);
        c[3] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[3]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[3]);
        k0 = k0^aez_key->Itab[2]; m+=4; c+=4; mbytes-=64;
    }
    if (mbytes >= 32) {
        k1 = k0^aez_key->Itab[0];
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        c[1] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[1]);
        k0 = k0^aez_key->Itab[1]; m+=2; c+=2; mbytes-=32;
    }
    if (mbytes >= 16) {
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
    }
    *c_orig = delta ^ sigma ^ aesinv(aez_key->aesinv_key, offset, Y0);
}

void aez_encipher_mem_16_nonmultiple(aez_key_t *aez_key, __m128i delta, int abytes, __m128i *m, int mbytes, __m128i *c) {
    int i,j;
    __m128i offset, tmp, X0, Y0;
    __m128i sigma = _mm_setzero_si128(), J = aez_key->J;
    __m128i k0 = bswap16(J), k1, k2, k3, buf[10];
    __m128i *m_orig=m, *c_orig=c;
    ALIGN(16) byte Yp[16], Ypp[16], Xp[16], Xpp[16], buf16[16], buf32[32] = {0};
    
    tmp = AHash(aez_key, abytes, m+1, mbytes-16);
    offset = aez_key->Ltab[3] ^ aez_key->Ltab[1];
    X0 = aes(aez_key->aes_key, offset, delta ^ tmp ^ *m);
    Y0 = aes(aez_key->aes_key, aez_key->Ltab[0], X0);

    m++; c++; mbytes-=16;
    while (mbytes > 128+16) {
        J = double_block(J);
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        c[1] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[1]);
        c[2] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[2]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[2]);
        c[3] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[3]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[3]);
        k0 ^= aez_key->Itab[2]; k1 ^= aez_key->Itab[2]; k2 ^= aez_key->Itab[2]; k3 ^= aez_key->Itab[2];
        c[4] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[4]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[4]);
        c[5] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[5]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[5]);
        c[6] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[6]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[6]);
        c[7] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[7]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[7]);
        k0 = bswap16(J); m+=8; c+=8; mbytes-=128;
    }
    if (abytes) {
        for (i=0; i*16 < mbytes; i++)                  buf[i] = m[i];
        for (i=mbytes; i<mbytes+abytes; i++) ((byte *)buf)[i] = 0;
        m = buf;
        mbytes = i;
    }
    if (mbytes >= 128+16) {
        J = double_block(J);
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        c[1] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[1]);
        c[2] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[2]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[2]);
        c[3] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[3]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[3]);
        k0 ^= aez_key->Itab[2]; k1 ^= aez_key->Itab[2]; k2 ^= aez_key->Itab[2]; k3 ^= aez_key->Itab[2];
        c[4] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[4]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[4]);
        c[5] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[5]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[5]);
        c[6] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[6]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[6]);
        c[7] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[7]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[7]);
        k0 = bswap16(J); m+=8; c+=8; mbytes-=128;
    }
    __m128i offsets[9];
    offsets[0] = k0;
    offsets[1] = k0^aez_key->Itab[0];
    offsets[2] = k0^aez_key->Itab[1];
    offsets[3] = offsets[1]^aez_key->Itab[1];
    offsets[4] = offsets[0]^aez_key->Itab[2];
    offsets[5] = offsets[1]^aez_key->Itab[2];
    offsets[6] = offsets[2]^aez_key->Itab[2];
    offsets[7] = offsets[3]^aez_key->Itab[2];
    offsets[8] = bswap16(double_block(J));
    i=0;
    if (mbytes >= 64+16) {
        k0 = offsets[i]; k1 = offsets[i+1]; k2 = offsets[i+2]; k3 = offsets[i+3]; 
        k1 = k0^aez_key->Itab[0]; k2 = k0^aez_key->Itab[1]; k3 = k1^aez_key->Itab[1];
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        c[1] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[1]);
        c[2] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k2^m[2]) ^Y0^k2;
        sigma ^= aes4(aez_key->aes_key, k2, c[2]);
        c[3] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k3^m[3]) ^Y0^k3;
        sigma ^= aes4(aez_key->aes_key, k3, c[3]);
        i+=4; m+=4; c+=4; mbytes-=64;
    }
    if (mbytes >= 32+16) {
        k0 = offsets[i]; k1 = offsets[i+1]; 
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        c[1] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k1^m[1]) ^Y0^k1;
        sigma ^= aes4(aez_key->aes_key, k1, c[1]);
        i+=2; m+=2; c+=2; mbytes-=32;
    }
    if (mbytes >= 16+16) {
        k0 = offsets[i];
        c[0] = aes(aez_key->aes_key, aez_key->Ltab[0], X0^k0^m[0]) ^Y0^k0;
        sigma ^= aes4(aez_key->aes_key, k0, c[0]);
        i+=1; m+=1; c+=1; mbytes-=16;
    }
    // Should be 17-31 bytes left
    *(__m128i*)Ypp = aes(aez_key->aes_key, aez_key->Ltab[0], X0^offsets[i]^m[0]); 
    // Save Ypp, update Ypp
    *(__m128i*)Yp = *(__m128i*)Ypp;
    *(__m128i*)buf16 = X0 ^ offsets[i+1] ^ m[1];
    for (j=mbytes%16; j<16; j++)   buf16[j] = Ypp[j];
    *(__m128i*)Ypp = aes(aez_key->aes_key, aez_key->Ltab[0], *(__m128i*)buf16);
    // Write c[0], integrate into AHash
    c[0] = Y0 ^ offsets[i] ^ *(__m128i*)Ypp;
    sigma ^= aes4(aez_key->aes_key, offsets[i], c[0]);
    // Write c[0], integrate into AHash
    *(__m128i*)buf16 = Y0 ^ offsets[i+1] ^ *(__m128i*)Yp;
    for (j=0; j<mbytes%16; j++) ((byte *)c)[16+j] = buf16[j];
    buf16[j++] = 0x80;
    for (   ; j<16; j++) buf16[j] = 0;
    sigma ^= aes4(aez_key->aes_key, offsets[i+1], *(__m128i*)buf16);
    *c_orig = delta ^ sigma ^ aesinv(aez_key->aesinv_key, offset, Y0);
}

void aez_encipher_mem_17_to_31(aez_key_t *aez_key, __m128i delta, int abytes, byte *m, int mbytes, byte *c) {
    int i;
    __m128i offset, tmp, X0, Y0, J=bswap16(aez_key->J);
    // Calculate X0 (AMAC of M^delta) and Y0
    ALIGN(16) byte Y1[16], buf16[16], buf32[32] = {0};
    for (i=0;i<mbytes; i++) buf32[i] = m[i];
    buf32[mbytes+abytes]=0x80;
    tmp = aes4(aez_key->aes_key, J, *(__m128i*)(buf32+16));
    offset = aez_key->Ltab[3] ^ aez_key->Ltab[1];
    X0 = aes(aez_key->aes_key, offset, delta ^ tmp ^ *(__m128i*)buf32);
    Y0 = aes(aez_key->aes_key, aez_key->Ltab[0], X0);
    // Save Y0, update Y0
    *(__m128i*)Y1 = Y0;
    *(__m128i*)buf16 = X0 ^ J ^ *(__m128i*)(buf32+16);
    for (i=(mbytes+abytes)%16; i<16; i++)   buf16[i] = Y1[i];
    Y0 = aes(aez_key->aes_key, aez_key->Ltab[0], *(__m128i*)buf16);
    // Write C1, prepare copy of C1 for AMAC
    *(__m128i*)buf16 = Y0 ^ J ^ *(__m128i*)Y1;
    for (i=0; i<(mbytes+abytes)%16; i++) c[16+i] = buf16[i];
    buf16[i++] = 0x80;
    for (   ; i<16; i++) buf16[i] = 0;
    tmp = aes4(aez_key->aes_key, J, *(__m128i*)buf16);
    *(__m128i*)c = delta ^ tmp ^ aesinv(aez_key->aesinv_key, offset, Y0);
}

void aez_encipher_mem(aez_key_t *aez_key, int abytes, byte *n, int nbytes, byte *ad,
                    int adbytes, byte *m, int mbytes, byte *c) {
    __m128i offset;
    if (adbytes%16) offset = aez_key->Ltab[3] ^ aez_key->Ltab[0];
    else            offset = aez_key->Ltab[2];
    __m128i delta = AMAC_tweak(aez_key, offset, abytes, n, nbytes, ad, adbytes);
    if (mbytes+abytes<32) {
        aez_encipher_mem_17_to_31(aez_key, delta, abytes, m, mbytes, c);
    } else if ((mbytes+abytes)%16==0) {
        aez_encipher_mem_16_multiple(aez_key, delta, abytes, (__m128i *)m, mbytes, (__m128i *)c); 
    } else if ((mbytes+abytes)%16!=0) {
        aez_encipher_mem_16_nonmultiple(aez_key, delta, abytes, (__m128i *)m, mbytes, (__m128i *)c); 
    }
} 

/* ------------------------------------------------------------------------- */

void Encrypt(aez_key_t *aez_key, int abytes, byte *n, int nbytes, byte *ad,
                    int adbytes, byte *m, int mbytes, byte *c) {
// Possibly unsafe reads of m, if m is < 16 bytes before a page boundary
    int i;
    __m128i offset, tmp;
    ALIGN(16) byte buf[16];
    if (mbytes==0) {
        if (abytes==0) return;
        offset = aez_key->Ltab[3];
        if (adbytes%16) offset ^= aez_key->Ltab[2] ^ aez_key->Ltab[0];
        *(__m128i*)buf = AMAC_tweak(aez_key, offset, abytes, n, nbytes, ad, adbytes);
        for (int i=0; i<abytes; i++) c[i]=buf[i];
    } else if (abytes+mbytes==16) {
        if (adbytes%16) offset = aez_key->Ltab[3] ^ aez_key->Ltab[2];
        else offset = aez_key->Ltab[2] ^ aez_key->Ltab[1] ^ aez_key->Ltab[0];
        offset = AMAC_tweak(aez_key, offset, abytes, n, nbytes, ad, adbytes);
        *(__m128i*)buf = _mm_loadu_si128((__m128i*)m);
        for (int i=mbytes; i<16; i++) buf[i]=0;
        tmp = aes(aez_key->aes_key, aez_key->Ltab[1] ^ aez_key->Ltab[0], *(__m128i*)buf ^ offset);
        _mm_storeu_si128((__m128i*)c, tmp ^ offset);
    } else if (abytes+mbytes < 16) {
        ALIGN(16) byte buf[16];
        *(__m128i *)buf = _mm_setzero_si128();
        for (i=0; i<mbytes; i++) buf[i] = m[i];
        aez_encipher_ff0(aez_key, abytes, n, nbytes, ad, adbytes, buf, mbytes+abytes, c); 
    } else /* abytes+mbytes > 16 */ {
        aez_encipher_mem(aez_key, abytes, n, nbytes, ad, adbytes, m, mbytes, c); 
    }
}

/* ------------------------------------------------------------------------- */

/*
 // Benchmarking 
 */
#include "aez.h"

#include <time.h>
#include <stdlib.h>
#include <string.h>
#define ABYTES 2
#define MAX 10
#define HZ (2.9e9)

#if !defined (ALIGN16)
# if defined (__GNUC__)
# define ALIGN16 __attribute__ ( (aligned (16)))
# else
# define ALIGN16 __declspec (align (16))
# endif
#endif

#define ITERS 100000
#define BLKS 128
#define BYTES 4096

int main() {
    ALIGN(16) aez_key_t aez_key;
    ALIGN(16) byte k[16] = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6};
    ALIGN(16) byte n[12] = {1,2,3,0};
    ALIGN(16) byte m[BYTES];
    ALIGN(16) byte c[sizeof(m)+16];

    __m128i res = _mm_setzero_si128();
    clock_t clk;
    double total_cycles;
    double total_bytes;
    
    /* --------------------------------------------------------------------- */
    aez_keyvector_t key; 
    aez_extract(&key, k, sizeof(k)); 
    clk = clock();
    for (int i=0; i < ITERS; i++) {
        aez_encrypt(c, m, n, NULL, sizeof(m), sizeof(n), 0, 0, &key); 
        res ^= *(__m128i *)c; 
    }
    clk = clock() - clk;
    total_cycles = clk*HZ/CLOCKS_PER_SEC;
    total_bytes = (double)ITERS*BYTES;
    printf("mine: %.3f cpb\n", total_cycles/total_bytes);
    pbuf(c, 16, 0);
    
    /* --------------------------------------------------------------------- */
    aez_key_setup(aez_extract_key(k, sizeof(k)) , &aez_key);
    
    clk = clock();
    for (int i=0; i < ITERS; i++) {
        Encrypt(&aez_key, 0, n, sizeof(n), NULL, 0, m, sizeof(m), c);
        res ^= *(__m128i *)c; 
    }
    clk = clock() - clk;
    total_cycles = clk*HZ/CLOCKS_PER_SEC;
    total_bytes = (double)ITERS*BYTES;
    printf("aez_ni: %.3f cpb\n", total_cycles/total_bytes);
    pbuf(c, 16, 0);




    return *(long long *)&res == 0;
}

int mainx() {
    ALIGN(16) aez_key_t aez_key;
    ALIGN(16) byte kin[] = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6};
    ALIGN(16) byte m[MAX];
    ALIGN(16) byte c[sizeof(m)+ABYTES];
    ALIGN(16) byte n[12] = {1,2,3,0};
    ALIGN(16) byte ad[12] = {1,2,3,0};

    for (int i=0; i<MAX; i++) m[i] = (byte)(i*i+47);

    aez_key_setup(aez_extract_key(kin, sizeof(kin)) , &aez_key);

    /*
    for (int i=0; i<256; i++) {
        for (int j=0; j<256; j++) {
            byte buf[2];
            buf[0] = i; buf[1] = j;
            Encrypt(&aez_key, 0, n, sizeof(n), ad, sizeof(ad), buf, 2, c);
            pbuf(c, 2, 0);
        }
    }
    */

    for (int i=0; i<MAX; i++) {
        Encrypt(&aez_key, ABYTES, n, sizeof(n), ad, sizeof(ad), m, i, c);
        pbuf(c, i+ABYTES, 0);
    }
    return 0;
}

