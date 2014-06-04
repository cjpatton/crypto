#include "aez.h"
#include "../portable.h"
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>

void aez_amac(aez_block_t mac, 
              const uint8_t *plaintext, 
              const aez_keyvector_t *key, 
              int i)
{

}

/* 
 * TODO Decrypter still needs to have encryption key 
 * around to compute this function correctly. Fix the 
 * way keys are done!!
 */ 
void aez_ahash(aez_block_t hash, 
               const uint8_t *plaintext, 
               size_t msg_bytes, 
               const aez_keyvector_t *key)
{
  int j; 
  aez_block_t tmp;
  ZERO_BLOCK(tmp); 
  ZERO_BLOCK(hash);

  for (j = 0; j < msg_bytes - AEZ_BYTES; j += AEZ_BYTES)
  {
    

  }
}


