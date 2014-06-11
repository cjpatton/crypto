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
 */
int encipher_mem(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key)
{
  return msg_bytes;
}

/*
 *
 */
int decipher_mem(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 aez_keyvector_t *key)
{
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
