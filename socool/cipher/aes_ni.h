/* aes_ni.h -- AES-128 calls for the AES-NI intrinsic instruction 
 * set on modern Intel x86 processors. This comes from Ted Krovetz' 
 * optimized AEZ implementation. */

#include <stdint.h>
#include <wmmintrin.h>
#include <tmmintrin.h>

typedef unsigned char byte;

#define ALIGN(n) __attribute__ ((aligned(n)))

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

void aes_setup(__m128i key, __m128i *rk);

void aes_setup_inv(__m128i key, __m128i *rk_inv, __m128i *rk);

__m128i aes(__m128i key[11], __m128i in);

__m128i aesinv(__m128i key[11], __m128i in);

void aes_cipher(byte *out, const byte *in, 
                __m128i key[11], unsigned inv);
