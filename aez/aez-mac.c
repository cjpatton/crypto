#include "aez.h"
#include "../portable.h"
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>


/*
 *
 */
void aez_amac(uint8_t *mac, 
              const uint8_t *plaintext, 
              aez_keyvector_t *key, 
              int i)
{
  // TODO 
}


/*
 *
 */ 
void aez_ahash(int8_t *hash, 
               const uint8_t *plaintext,
               size_t msg_bytes, 
               aez_keyvector_t *key)
{
  assert((msg_bytes / 16) < key->msg_length); 
  
  int i=0, j; 
  uint8_t tmp [AEZ_BYTES];
  ZERO_BLOCK((uint32_t *)hash);
  
  for (j = 0; j < msg_bytes; j += AEZ_BYTES) 
  {
    aez_cipher(tmp, plaintext + j, key->Khash[i++], key, ENCRYPT, 4); 
    XOR_BLOCK((uint32_t *)hash, (uint32_t *)tmp); 
  }

  /* Pad last block */ 
  if (j > msg_bytes) 
  {
    ZERO_BLOCK((uint32_t *)tmp); 
    j -= AEZ_BYTES; 
    memcpy(tmp, plaintext + j, sizeof(uint8_t) * (msg_bytes - j));
    tmp[msg_bytes - j] = 1; 
    aez_cipher(tmp, tmp, key->Khash[i++], key, ENCRYPT, 4); 
    XOR_BLOCK((uint32_t *)hash, (uint32_t *)tmp); 
  }
}
