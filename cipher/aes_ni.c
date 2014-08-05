/* aes_ni.c -- AES-128 calls for the AES-NI intrinsic instruction 
 * set on modern Intel x86 processors. This comes from Ted Krovetz' 
 * optimized AEZ implementation. */

#include "aes_ni.h"

typedef unsigned char byte;

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

__m128i aesinv(__m128i key[11], __m128i in) 
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


void aes_cipher(byte *out, const byte *in, 
                __m128i key[11], unsigned inv)
{
  __m128i tmp; 
  ALIGN(16) byte buf[16]; 
  
  /* Pad message. If message is less than 16 bytes, use
   *  `*(__m128i*)buf = _mm_setzero_si128();
   *   for (i = 0; i < msg_bytes; i++) buf[i] = in[i];` */
  *(__m128i*)buf = _mm_loadu_si128((__m128i*)in);

  /* Encipher or decipher. */ 
  if (!inv) 
    *(__m128i*)buf = aes(key, *(__m128i*)buf); 
  else
    *(__m128i*)buf = aesinv(key, *(__m128i*)buf); 

  /* Store output in buffer. */ 
  _mm_storeu_si128((__m128i*)out, *(__m128i*)buf); 

}
