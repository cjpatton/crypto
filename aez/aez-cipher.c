/*
 * aez-cipher.c -- Message enciphering in the AEZ authenticated
 * encryption scheme. Encipher, Decipher, EncipherMEM, DecipherMEM,  
 * EncipherFF0, and DecipherFF0. (The last two are implemented in 
 * cipher_ff0() with an inversion argument.) 
 * 
 * Christopher Patton <chrispatton@gmail.com>, June 2014.
 */ 

#include "aez.h"
#include "../portable.h"
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>


/* 
 * Local function declarations (definitions below).  
 */

void complement_if_needed(uint8_t *tweak, size_t bytes,
                          const uint8_t *src, uint8_t *dst);

int cipher_ff0(uint8_t *out, 
               const uint8_t *in, 
               const uint8_t *tag, 
               size_t msg_bytes,
               size_t tag_bytes, 
               unsigned inv, 
               aez_keyvector_t *key);

int encipher_mem(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key);

int decipher_mem(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key);


/* ------------------------------------------------------------------------ */
                     
/*
 * The AEZ enciphering scheme. Calls EncipherMEM() and
 * EncipherFF0(). 
 */
int aez_encipher(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key)
{
  if (msg_bytes < AEZ_BYTES) // FF0
   return cipher_ff0(out, in, tag, msg_bytes, tag_bytes, 0, key); 

  else if (msg_bytes == AEZ_BYTES)
  {
    uint8_t tweak [AEZ_BYTES]; 
    aez_amac(tweak, tag, tag_bytes, key, 3);
    CP_BLOCK(out, in);
    XOR_BLOCK(out, tweak); 
    aez_blockcipher(out, out, key->Kone, key, ENCRYPT, 10); 
    XOR_BLOCK(out, tweak); 
    return AEZ_BYTES; 
  }

  else // MEM
   return encipher_mem(out, in, tag, msg_bytes, tag_bytes, key); 

}

/*
 * The AEZ deciphering scheme. Calls DecipherMEM() and
 * DecipherFF0(). 
 */
int aez_decipher(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key)
{
  if (msg_bytes < AEZ_BYTES) // FF0
    return cipher_ff0(out, in, tag, msg_bytes, tag_bytes, 1, key); 
 
  else if (msg_bytes == AEZ_BYTES) // |m| = 16
  {
    uint8_t tweak [AEZ_BYTES]; 
    aez_amac(tweak, tag, tag_bytes, key, 3); 
    CP_BLOCK(out, in);
    XOR_BLOCK(out, tweak); 
    aez_blockcipher(out, out, key->Kone, key, DECRYPT, 10); 
    XOR_BLOCK(out, tweak); 
    return AEZ_BYTES; 
  }

  else // MEM
    return decipher_mem(out, in, tag, msg_bytes, tag_bytes, key); 
}


/* ------------------------------------------------------------------------ */

/*
 * EncipherMEM - encipher messages longer than 16 bytes. This is 
 * the meat of the AEZ scheme. This is based on the Naor, Reingold
 * electronic codebook scheme. See [24] in the AEZ reference.
 */
int encipher_mem(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key)
{
  if (msg_bytes <= AEZ_BYTES)
    return (int)aez_MSG_LENGTH; 
  aez_reset_variant(key); 

  int i, j=0;  
  aez_block_t tweak, prev, X0, Y0, K, Kprev;
  uint32_t *offset; 
  
  memcpy(out, in, msg_bytes * sizeof(uint8_t)); 
  
  /* Mix tweak into first block. */ 
  aez_amac((uint8_t *)tweak, tag, tag_bytes, key, 0); 
  XOR_BLOCK(out, tweak); 
  
  /* X0 - AMAC() is a PRF taken over the whole message. When tweaked with 
   * the offset Ki, each AES call on the message blocks is an independent
   * PRP. */ 
  aez_amac((uint8_t *)X0, out, msg_bytes, key, 1);

  /* Y0 */ 
  aez_blockcipher((uint8_t *)Y0, (uint8_t *)X0, key->Kecb, key, ENCRYPT, 10);
  CP_BLOCK(prev, Y0); 

  for (i = AEZ_BYTES; i < msg_bytes - AEZ_BYTES; i += AEZ_BYTES)
  {
    aez_variant(K, key, i + 1, (j++) % 8, 0, 0); 
    XOR_BLOCK(&out[i], X0); 
    XOR_BLOCK(&out[i], K); 
    aez_blockcipher(&out[i], &out[i], key->Kecb, key, ENCRYPT, 10); 
    CP_BLOCK(prev, &out[i]); 
    XOR_BLOCK(&out[i], Y0); 
    XOR_BLOCK(&out[i], K); 
  }

  if (i == msg_bytes - AEZ_BYTES) /* Unfragmented last block */ 
  {
    aez_variant(K, key, i + 1, (j++) % 8, 0, 0); 
    XOR_BLOCK(&out[i], X0); 
    XOR_BLOCK(&out[i], K); 
    aez_blockcipher(&out[i], &out[i], key->Kecb, key, ENCRYPT, 10);
    XOR_BLOCK(&out[i], Y0); 
    XOR_BLOCK(&out[i], K); 
    offset = key->Kmac[1]; 
  }

  else /* Fragmented last block */ 
  {
    uint8_t tmp [16]; 
    int m = i; 
    CP_BLOCK(Kprev, K);
    aez_variant(K, key, i + 1, (j++) % 8, 0, 0); 

    /* Xm || R - input to last cipher call. */ 
    CP_BLOCK(tmp, prev); 
    for (i = 0; i < msg_bytes - m; i++)
    {
      tmp[i]  = out[i + m]; 
      tmp[i] ^= ((uint8_t *)X0)[i];
      tmp[i] ^= ((uint8_t *)K)[i];
    }

    /* Ym-1, Cm-1 */ 
    i = m - AEZ_BYTES;
    aez_blockcipher(&out[i], tmp, key->Kecb, key, ENCRYPT, 10); 
    if (msg_bytes > 32)
    {
      XOR_BLOCK(&out[i], Y0); 
      XOR_BLOCK(&out[i], Kprev); 
    }
    else 
    {
      CP_BLOCK(Y0, &out[i]); 
    }

    /* Ym-1 -> Ym, Cm */ 
    for (i = 0; i < msg_bytes - m; i++)
    {
      out[i + m]  = ((uint8_t *)prev)[i];
      out[i + m] ^= ((uint8_t *)Y0)[i]; 
      out[i + m] ^= ((uint8_t *)K)[i]; 
    }

    offset = key->Kmac1[1]; 
  }
  
  /* Apply AMAC in reverse on C0. */ 
  aez_blockcipher((uint8_t *)Y0, (const uint8_t *)Y0, offset, key, DECRYPT, 10); 
  aez_ahash((uint8_t *)out, &out[AEZ_BYTES], msg_bytes - AEZ_BYTES, key);
  XOR_BLOCK(out, Y0); 

  /* Unmix tweak. */ 
  XOR_BLOCK(out, tweak); 
  
  aez_reset_variant(key); 
  return msg_bytes;  
}

/*
 * DecipherMEM - decipher messages longer than 16 bytes. 
 */
int decipher_mem(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key)
{
  if (msg_bytes <= AEZ_BYTES)
    return (int)aez_MSG_LENGTH; 
  aez_reset_variant(key); 
  
  int i, j=0;
  aez_block_t tweak, prev, Y0, X0, K, Kprev;
  uint32_t *offset; 
  
  memcpy(out, in, msg_bytes * sizeof(uint8_t)); 
  
  /* Mix tweak into first block. */ 
  aez_amac((uint8_t *)tweak, tag, tag_bytes, key, 0); 
  XOR_BLOCK(out, tweak); 
  
  /* Y0 - AMAC() is a PRF taken over the whole message. When tweaked with 
   * the offset Ki, each AES call on the message blocks is an independent
   * PRP. */ 
  aez_amac((uint8_t *)Y0, out, msg_bytes, key, 1);

  /* X0 */ 
  aez_blockcipher((uint8_t *)X0, (uint8_t *)Y0, key->Kecb, key, DECRYPT, 10);
  CP_BLOCK(prev, X0); 

  for (i = AEZ_BYTES; i < msg_bytes - AEZ_BYTES; i += AEZ_BYTES)
  {
    aez_variant(K, key, i + 1, (j++) % 8, 0, 0); 
    XOR_BLOCK(&out[i], K); 
    XOR_BLOCK(&out[i], Y0); 
    aez_blockcipher(&out[i], &out[i], key->Kecb, key, DECRYPT, 10); 
    CP_BLOCK(prev, &out[i]); 
    XOR_BLOCK(&out[i], K); 
    XOR_BLOCK(&out[i], X0); 
  }

  if (i == msg_bytes - AEZ_BYTES) /* Unfragmented last block */ 
  {
    aez_variant(K, key, i + 1, (j++) % 8, 0, 0); 
    XOR_BLOCK(&out[i], K); 
    XOR_BLOCK(&out[i], Y0); 
    aez_blockcipher(&out[i], &out[i], key->Kecb, key, DECRYPT, 10); 
    XOR_BLOCK(&out[i], K); 
    XOR_BLOCK(&out[i], X0); 
    offset = key->Kmac[1]; 
  }

  else /* Fragmented last block */ 
  {
    uint8_t tmp [16]; 
    int m = i; 
    CP_BLOCK(Kprev, K);
    aez_variant(K, key, i + 1, (j++) % 8, 0, 0); 
    
    /* prev -> Ymp1 */ 
    CP_BLOCK(tmp, prev); 

    /* Cm, Ym -> Ym || R */ 
    for (i = 0; i < msg_bytes - m; i++)
    {
      out[i + m] ^= ((uint8_t *)Y0)[i]; 
      out[i + m] ^= ((uint8_t *)K)[i]; 
      ((uint8_t *)tmp)[i] = out[i + m]; 
    }
  
    /* Ym || R -> Mm-1 */
    i = m - AEZ_BYTES; 
    aez_blockcipher(&out[i], tmp, key->Kecb, key, DECRYPT, 10);  
    if (msg_bytes > 32)
    {
      XOR_BLOCK(&out[i], Kprev); 
      XOR_BLOCK(&out[i], X0); 
    }
    else
    {
      CP_BLOCK(X0, &out[i]); 
    }

    for (i = 0; i < msg_bytes - m; i++)
    {
      out[i + m]  = ((uint8_t *)prev)[i]; 
      out[i + m] ^= ((uint8_t *)X0)[i]; 
      out[i + m] ^= ((uint8_t *)K)[i]; 
    }

    offset = key->Kmac1[1]; 
  }
  
  /* Apply AMAC in reverse on M0. */ 
  aez_blockcipher((uint8_t *)X0, (const uint8_t *)X0, offset, key, DECRYPT, 10); 
  aez_ahash((uint8_t *)out, &out[AEZ_BYTES], msg_bytes - AEZ_BYTES, key);
  XOR_BLOCK(out, X0); 

  /* Unmix tweak. */ 
  XOR_BLOCK(out, tweak); 
  
  aez_reset_variant(key); 
  return msg_bytes; 
}


/* ------------------------------------------------------------------------ */

/*
 * CipherFF0 - encipher messages shorter than 16 bytes. This is 
 * based on an unbalanced Fesital network, the number of rounds 
 * depends on the size of the message. In order to mak this c
 * complient to the spec, I directly transcribed Ted Krovetz' 
 * solution here. 
 */
int cipher_ff0(uint8_t *out, 
               const uint8_t *in, 
               const uint8_t *tag, 
               size_t msg_bytes,
               size_t tag_bytes, 
               unsigned inv,
               aez_keyvector_t *key)
{
  int i, k, l;
  uint8_t mask=0x00, pad=0x80, 
          tweak [AEZ_BYTES], 
          front [AEZ_BYTES],
          back [AEZ_BYTES],
          tmp [AEZ_BYTES],
          *A, *B; 
  
  if (msg_bytes == 1) k = 24; 
  else if (msg_bytes == 2) k = 16;
  else k = 10; 
  aez_amac((uint8_t *)tweak, tag, tag_bytes, key, 2); 
  
  if (inv) { complement_if_needed(tweak, msg_bytes, in, tmp); in=tmp; }
  
  l = (msg_bytes+1) /2; 
  memcpy(front, in, l); 
  memcpy(back, in + msg_bytes/2, l); 

  if (msg_bytes & 1)
  {
    for (i=0; i < msg_bytes/2; i++)
      back[i] = (uint8_t)((back[i] << 4) | (back[i+1] >> 4));
    back[msg_bytes / 2] = (uint8_t)(back[msg_bytes/2] << 4);
    pad = 0x08; mask = 0xf0;
  }

  if (inv) { B = front; A = back; } else { A = front; B = back; }
  
  for (i = 1; i <= k; i+= 2)
  {
    ZERO_BLOCK(tmp); 
    tmp[3] = (uint8_t)(inv ? k + 1 - i : i); 
    memcpy(&tmp[4], B, l);
    tmp[4+msg_bytes/2] = (tmp[4+msg_bytes/2] & mask) | pad;
    XOR_BLOCK(tmp, tweak);
    aez_blockcipher(tmp, tmp, key->Kff0, key, ENCRYPT, 4); 
    XOR_BLOCK(A, tmp); 

    ZERO_BLOCK(tmp); 
    tmp[3] = (uint8_t)(inv ? k - i: i + 1); 
    memcpy(&tmp[4], A, l);
    tmp[4+msg_bytes/2] = (tmp[4+msg_bytes/2] & mask) | pad;
    XOR_BLOCK(tmp, tweak);
    aez_blockcipher(tmp, tmp, key->Kff0, key, ENCRYPT, 4); 
    XOR_BLOCK(B, tmp); 
  }
    
  memcpy(tmp,             front, msg_bytes/2);
  memcpy(tmp+msg_bytes/2, back, (msg_bytes+1)/2);
  if (msg_bytes & 1) 
  {
    for (i=msg_bytes - 1; i > msg_bytes/2; i--)
       tmp[i] = (uint8_t)((tmp[i] >> 4) | (tmp[i-1] << 4));
     tmp[msg_bytes/2] = (uint8_t)((back[0] >> 4) | (front[msg_bytes/2] & mask));
  }
  if (inv) memcpy(out,tmp,msg_bytes);
  else complement_if_needed(tweak, msg_bytes, tmp, out);
  return msg_bytes;
}

/* 
 * Written by Ted Krovetz for the reference implementation of AEZ.
 */
void complement_if_needed(uint8_t *tweak, size_t bytes,
                          const uint8_t *src, uint8_t *dst) 
{
    uint8_t comp[16], and_sum=0xff, or_sum=0x00;
    unsigned i;
    for (i=0; i<bytes; i++) {
        and_sum &= src[i];
        or_sum |= src[i];
        comp[i] = (uint8_t)~src[i];
    }
    unsigned delta_bit = ( tweak[(bytes-1)/8] >> ((16-bytes)%8) ) & 1;
    if ( (delta_bit + (and_sum==0xff) + (or_sum==0x00)) == 2 )
         memcpy(dst,comp,bytes);
    else memcpy(dst,src,bytes);
}



/* ------------------------------------------------------------------------ */

/* 
 * WARNING -- deprecated
 * My original approach to FF0. This worked, but it didn't actually
 * split the message across bits. cipher_ff0() conforms to the spec
 * better. (Just thought I'd keep this around just in case it's 
 * interesting later.) 
 */

void point_swap(uint8_t *out, const uint8_t *tweak, size_t msg_bytes);

/*
 * EncipherFF0 - encipher messages shorter than 16 bytes. This is 
 * based on an unbalanced Fesital network, the number of rounds 
 * depends on the size of the message.
 */
int encipher_ff0(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key)
{
  int i, j, k, l;
  uint8_t tweak [AEZ_BYTES], tmp [AEZ_BYTES];
  uint8_t A [AEZ_BYTES], B [AEZ_BYTES]; 
  
  if (msg_bytes == 1) k = 24; 
  else if (msg_bytes == 2) k = 16;
  else k = 10; 
  aez_amac((uint8_t *)tweak, tag, tag_bytes, key, 2); 
  
  memcpy(out, in, msg_bytes); 
  l = (msg_bytes / 2) + 1; 

  for (i = 1; i <= k; i++)
  {
    ZERO_BLOCK(A); memcpy(A, out, l); 
    ZERO_BLOCK(B); memcpy(B, &out[l], msg_bytes - l); 
    
    ZERO_BLOCK(tmp); 
    *(uint32_t *)tmp = i; /* TODO byte order */  
    memcpy(&tmp[4], B, msg_bytes - l); 
    tmp[4 + msg_bytes - l] = 1; 

    XOR_BLOCK(tmp, tweak);
    aez_blockcipher(tmp, tmp, key->Kff0, key, ENCRYPT, 4); 

    for (j = 0; j < l; j++)
      tmp[j] ^= A[j];

    memcpy(out, B, msg_bytes - l); 
    memcpy(&out[msg_bytes - l], tmp, l); 
  }
  
  point_swap(out, tweak, msg_bytes);

  return msg_bytes;
}

/*
 * DecipherFF0 - decipher messages shorter than 16 bytes. 
 */
int decipher_ff0(uint8_t *out,
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key)
{
  int i, j, k, l;
  uint8_t tweak [AEZ_BYTES], tmp [AEZ_BYTES];
  uint8_t A [AEZ_BYTES], B [AEZ_BYTES]; 
  
  if (msg_bytes == 1) k = 24; 
  else if (msg_bytes == 2) k = 16;
  else k = 10; 
  
  memcpy(out, in, msg_bytes); 
  aez_amac((uint8_t *)tweak, tag, tag_bytes, key, 2); 
  point_swap(out, tweak, msg_bytes);
 
  l = (msg_bytes / 2) + 1; 
  for (i = k; i > 0; i--)
  {
    ZERO_BLOCK(B); memcpy(B, out, msg_bytes - l); 
    ZERO_BLOCK(A); memcpy(A, &out[msg_bytes - l], l); 
    
    ZERO_BLOCK(tmp); 
    *(uint32_t *)tmp = i; /* TODO byte order */ 
    memcpy(&tmp[4], B, msg_bytes - l); 
    tmp[4 + msg_bytes - l] = 1; 

    XOR_BLOCK(tmp, tweak);
    aez_blockcipher(tmp, tmp, key->Kff0, key, ENCRYPT, 4); 

    for (j = 0; j < l; j++)
      tmp[j] ^= A[j];

    memcpy(out, tmp, l); 
    memcpy(&out[l], B, msg_bytes - l); 

  }
  
  return msg_bytes;
}

/* 
 * When a tweak-dependent pseudo random bit comes up True, 
 * swap two points in the message and ciphertext domains. 
 * Used in [27] (see AEZ spec) to address the fact that 
 * Feistel networks only generate even permuataions. 
 *
 * TODO This is a potential timing-attack channel, a fact
 *      that is addressed in the latest revision of the 
 *      AEZ spec.
 */ 
void point_swap(uint8_t *out, const uint8_t *tweak, size_t msg_bytes)
{
  int i, j, k;
  if (tweak[msg_bytes - 1] & 1)
  {
    j = 1; 
    for (i = 0; i < msg_bytes; i++)
      if (out[i] != 255) 
        j = 0; 
    k = 1; 
    for (i = 0; i < msg_bytes; i++)
      if (out[i] != 0)
        k = 0; 
    if (j || k)
      for (i = 0; i < msg_bytes; i++)
        out[i] ^= 255;   
  }
}
