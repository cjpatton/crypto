#include "aez.h"
#include "../portable.h"
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* 
 * Local function declarations (definitions below).  
 */

int encipher_ff0(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key);

int decipher_ff0(uint8_t *out,
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
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
   return encipher_ff0(out, in, tag, msg_bytes, tag_bytes, key); 

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
    return decipher_ff0(out, in, tag, msg_bytes, tag_bytes, key); 
 
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


/*
 * EncipherMEM - encipher messages longer than 16 bytes. This is 
 * the meat of the AEZ scheme. This is based on the Naor, Reingold
 * scheme. See [24] in the AEZ reference. 
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


/*
 * EncipherFF0 - encipher messages shorter than 16 bytes. This is 
 * based on a Fesital network, the number of rounds depending on the
 * size of the message. 
 */
int encipher_ff0(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key)
{
  return (int)aez_NOT_IMPLEMENTED;
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
  return (int)aez_NOT_IMPLEMENTED; 
}
