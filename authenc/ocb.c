/**
 * ocb.c -- Offset codebook mode of authenticated encryption, do to 
 * Phil Rogaway, John Black, and Ted Krovetz. This code differs from 
 * the OCB specification in that it borrows key tweaks from a more 
 * recent proposal called AEZ. 
 *
 * This program uses the AES-NI instructions for modern x86 processors. 
 * Compile with gcc flags "-O3 -std=c99 -maes -mssse3". The code for 
 * the AES was written by Ted Krovetz. 
 *
 *   Written by Christopher Patton.
 *
 * This program is dedicated to the public domain. 
 */

/*
 * Last modified 10 Aug 2014.
 */

#include <stdint.h>
#include <wmmintrin.h>
#include <tmmintrin.h>
#include <string.h>
#include <stdio.h>


#define ALIGN(n) __attribute__ ((aligned(n)))

typedef unsigned char Byte;
typedef ALIGN(16) Byte Block [16]; 

typedef struct {

 /* Tweaks */
 Block J, I[8];  
 
 /* Key schedules */ 
 Block enc [11], dec[11]; 
 
} OCBState; 



/* ----- AES key setup and blockcipher calls. ------------------------------ */


#define SETUP_STEP(v1,v2,v3,shuff_const,aes_const)                    \
    v2 = _mm_aeskeygenassist_si128(v1,aes_const);                     \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),        \
                                         _mm_castsi128_ps(v1), 16));  \
    v1 = _mm_xor_si128(v1,v3);                                        \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),        \
                                         _mm_castsi128_ps(v1), 140)); \
    v1 = _mm_xor_si128(v1,v3);                                        \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                           \
    v1 = _mm_xor_si128(v1,v2)

void aes_setup(__m128i key, __m128i *rk) 
{
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
  
void aes_setup_inv(__m128i key, __m128i *rk_inv, __m128i *rk) 
{
  if (rk == NULL)
  {
    __m128i key_sched [11]; 
    aes_setup(key, key_sched);
    rk = key_sched;
  }
  rk_inv[0] = rk[10];
  rk_inv[1] = _mm_aesimc_si128(rk[9]);
  rk_inv[2] = _mm_aesimc_si128(rk[8]);
  rk_inv[3] = _mm_aesimc_si128(rk[7]);
  rk_inv[4] = _mm_aesimc_si128(rk[6]);
  rk_inv[5] = _mm_aesimc_si128(rk[5]);
  rk_inv[6] = _mm_aesimc_si128(rk[4]);
  rk_inv[7] = _mm_aesimc_si128(rk[3]);
  rk_inv[8] = _mm_aesimc_si128(rk[2]);
  rk_inv[9] = _mm_aesimc_si128(rk[1]);
  rk_inv[10] = rk[0];
}

__m128i aes(__m128i key[11], __m128i in) 
{
  in = _mm_aesenc_si128 (in^key[0],key[1]);
  in = _mm_aesenc_si128 (in,key[2]);
  in = _mm_aesenc_si128 (in,key[3]);
  in = _mm_aesenc_si128 (in,key[4]);
  in = _mm_aesenc_si128 (in,key[5]);
  in = _mm_aesenc_si128 (in,key[6]);
  in = _mm_aesenc_si128 (in,key[7]);
  in = _mm_aesenc_si128 (in,key[8]);
  in = _mm_aesenc_si128 (in,key[9]);
  return _mm_aesenclast_si128 (in,key[10]);
} 

__m128i aes_inv(__m128i key[11], __m128i in) 
{
  in = _mm_aesdec_si128 (in^key[0],key[1]);
  in = _mm_aesdec_si128 (in,key[2]);
  in = _mm_aesdec_si128 (in,key[3]);
  in = _mm_aesdec_si128 (in,key[4]);
  in = _mm_aesdec_si128 (in,key[5]);
  in = _mm_aesdec_si128 (in,key[6]);
  in = _mm_aesdec_si128 (in,key[7]);
  in = _mm_aesdec_si128 (in,key[8]);
  in = _mm_aesdec_si128 (in,key[9]);
  return _mm_aesdeclast_si128 (in,key[10]);
}



/* ---- OCB initialization. ------------------------------------------------ */

void init(OCBState *state, const Byte K[])
{
  __m128i key = _mm_loadu_si128((__m128i *)K); 
  aes_setup(key, (__m128i *)state->enc); 
  aes_setup_inv(key, (__m128i *)state->dec, (__m128i *)state->dec);
} 



/* ---- OCB authenticated encryption. -------------------------------------- */

void encrypt(Byte *C, 
             Byte *T, 
             const Byte *M, 
             unsigned msg_len,
             unsigned tag_len, 
             OCBState *state)
{
  ALIGN(16) Byte buff [16];
  __m128i in, out, Z;
  unsigned i, full_blocks = msg_len - (msg_len % 16);  

  /* Unfragmented blocks */ 
  for (i = 0; i < full_blocks ; i += 16)
  {
    Z = _mm_setzero_si128(); // TODO tweak 
    in = _mm_loadu_si128((__m128i *)&M[i]); 
    out = aes((__m128i *)state->enc, in ^ Z) ^ Z; 
    _mm_storeu_si128((__m128i *)&C[i], out); 
  }
   
  /* Fragmented last block */
  // TODO 


}



/* ----- OCB authenticated decryption. ------------------------------------- */

int decrypt(Byte *M, 
            const Byte *C,
            const Byte *T,
            unsigned msg_len, 
            unsigned tag_len, 
            OCBState *state)
{
  // TODO 
  return 0; 
}



/* ----- Testing, testing ... ---------------------------------------------- */

int main() {
  
  Byte key [] =  {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};  
  OCBState state; 
  init(&state, key); 

  Byte message [1024] = "0000000000000000";
  Byte plaintext [1024], ciphertext [1024], tag [16];
  unsigned msg_len = strlen((const char *)message), 
           tag_len = 16; 

  encrypt(ciphertext, tag, message, msg_len, tag_len, &state); 




  return 0; 
}
