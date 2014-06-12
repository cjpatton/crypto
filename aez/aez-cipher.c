#include "aez.h"
#include "../portable.h"
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* 
 * Local function declarations. 
 */

int encipher_ff0(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key);

int decipher_ff0(uint8_t *out,
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key);
                     
int encipher_mem(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key);

int decipher_mem(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key);
                     


/*
 * tag_bytes == 32. 
 */
int aez_encipher(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key)
{
  if (msg_bytes < AEZ_BYTES) // FF0
   return encipher_ff0(out, in, tag, msg_bytes, key); 

  else if (msg_bytes == AEZ_BYTES)
  {
    uint8_t tweak [AEZ_BYTES]; 
    aez_amac(tweak, tag, 256, key, 3);
    CP_BLOCK(out, in);
    XOR_BLOCK(out, tweak); 
    aez_blockcipher(out, out, key->Kone, key, ENCRYPT, 10); 
    XOR_BLOCK(out, tweak); 
    return AEZ_BYTES; 
  }

  else // MEM
   return encipher_mem(out, in, tag, msg_bytes, key); 

}

/*
 *
 */
int aez_decipher(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key)
{
  if (msg_bytes < AEZ_BYTES) // FF0
    return decipher_ff0(out, in, tag, msg_bytes, key); 
 
  else if (msg_bytes == AEZ_BYTES)
  {
    uint8_t tweak [AEZ_BYTES]; 
    aez_amac(tweak, tag, 256, key, 3); // FIXME tag length
    CP_BLOCK(out, in);
    XOR_BLOCK(out, tweak); 
    aez_blockcipher(out, out, key->Kone, key, DECRYPT, 10); 
    XOR_BLOCK(out, tweak); 
    return AEZ_BYTES; 
  }

  else // MEM
    return decipher_mem(out, in, tag, msg_bytes, key); 
}

/*
 * TODO Check that message is shorter than vector.
 * TODO Check that message is greather than 16 bytes. 
 */
int encipher_mem(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key)
{
  int i, j=0;  
  aez_block_t tweak, prev, X0, Y0;
  uint32_t *offset; 
  
  memcpy(out, in, msg_bytes * sizeof(uint8_t)); 
  
  /* Mix tweak into first block. */ 
  aez_amac((uint8_t *)tweak, tag, 255, key, 0); // FIXME tag length
  XOR_BLOCK(out, tweak); 
  
  /* X0 - AMAC() is a PRF taken over the whole message. When tweaked with 
   * the offset Ki, each AES call on the message blocks is an independent
   * PSRP. */ 
  aez_amac((uint8_t *)X0, out, msg_bytes, key, 1);

  /* Y0 */ 
  aez_blockcipher((uint8_t *)Y0, (uint8_t *)X0, key->Kecb, key, ENCRYPT, 10);

  for (i = AEZ_BYTES; i < msg_bytes - AEZ_BYTES; i += AEZ_BYTES)
  {
    XOR_BLOCK(&out[i], X0); 
    XOR_BLOCK(&out[i], key->K[j]); 
    aez_blockcipher(&out[i], &out[i], key->Kecb, key, ENCRYPT, 10); 
    XOR_BLOCK(&out[i], Y0); 
    XOR_BLOCK(&out[i], key->K[j]); 
    ++j; 
  }

  if (i == msg_bytes - AEZ_BYTES) /* Unfragmented last block */ 
  {
    XOR_BLOCK(&out[i], X0); 
    XOR_BLOCK(&out[i], key->K[j]); 
    aez_blockcipher(&out[i], &out[i], key->Kecb, key, ENCRYPT, 10);
    XOR_BLOCK(&out[i], Y0); 
    XOR_BLOCK(&out[i], key->K[j]); 

    offset = key->Kmac[1]; 
  }

  else /* TODO Fragmented last block */ 
  {
    offset = key->Kmac1[1]; 
  }
  
  /* Apply AMAC in reverse on C0. */ 
  aez_blockcipher((uint8_t *)Y0, (const uint8_t *)Y0, offset, key, DECRYPT, 10); 
  aez_ahash((uint8_t *)out, &out[AEZ_BYTES], msg_bytes - AEZ_BYTES, key);
  XOR_BLOCK(out, Y0); 

  /* Unmix tweak. */ 
  XOR_BLOCK(out, tweak); 
  return msg_bytes;  
}

/*
 * TODO Check that message is shorter than vector.
 * TODO Check that message is greather than 16 bytes. 
 */
int decipher_mem(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key)
{
  int i, j=0;
  aez_block_t tweak, prev, Y0, X0;
  uint32_t *offset; 
  
  memcpy(out, in, msg_bytes * sizeof(uint8_t)); 
  
  /* Mix tweak into first block. */ 
  aez_amac((uint8_t *)tweak, tag, 255, key, 0); // FIXME tag length
  XOR_BLOCK(out, tweak); 
  
  /* Y0 - AMAC() is a PRF taken over the whole message. When tweaked with 
   * the offset Ki, each AES call on the message blocks is an independent
   * PSRP. */ 
  aez_amac((uint8_t *)Y0, out, msg_bytes, key, 1);

  /* X0 */ 
  aez_blockcipher((uint8_t *)X0, (uint8_t *)Y0, key->Kecb, key, DECRYPT, 10);

  for (i = AEZ_BYTES; i < msg_bytes - AEZ_BYTES; i += AEZ_BYTES)
  {
    XOR_BLOCK(&out[i], key->K[j]); 
    XOR_BLOCK(&out[i], Y0); 
    aez_blockcipher(&out[i], &out[i], key->Kecb, key, DECRYPT, 10); 
    XOR_BLOCK(&out[i], key->K[j]); 
    XOR_BLOCK(&out[i], X0); 
    ++j; 
  }

  if (i == msg_bytes - AEZ_BYTES) /* Unfragmented last block */ 
  {
    XOR_BLOCK(&out[i], key->K[j]); 
    XOR_BLOCK(&out[i], Y0); 
    aez_blockcipher(&out[i], &out[i], key->Kecb, key, DECRYPT, 10); 
    XOR_BLOCK(&out[i], key->K[j]); 
    XOR_BLOCK(&out[i], X0); 
    offset = key->Kmac[1]; 
  }

  else /* TODO Fragmented last block */ 
  {
    
    offset = key->Kmac1[1]; 
  }
  
  /* Apply AMAC in reverse on M0. */ 
  aez_blockcipher((uint8_t *)X0, (const uint8_t *)X0, offset, key, DECRYPT, 10); 
  aez_ahash((uint8_t *)out, &out[AEZ_BYTES], msg_bytes - AEZ_BYTES, key);
  XOR_BLOCK(out, X0); 

  /* Unmix tweak. */ 
  XOR_BLOCK(out, tweak); 
  return msg_bytes; 
}

                     
int encipher_ff0(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key)
{
  printf("FF0 patience.\n"); 
  return msg_bytes; 
}

int decipher_ff0(uint8_t *out,
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key)
{
  printf("FF0 unpatience.\n"); 
  return msg_bytes; 
}
