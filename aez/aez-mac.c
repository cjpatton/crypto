#include "aez.h"
#include "../portable.h"
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>


/*
 * AMAC - a message authentication code based AHash() (see below). 
 */
void aez_amac(uint8_t *mac, 
              const uint8_t *plaintext, 
              size_t msg_bytes,
              aez_keyvector_t *key, 
              int i)
{
  assert(0 <= i && i < 4); 
  
  uint8_t tmp [AEZ_BYTES];
  ZERO_BLOCK((uint32_t *)tmp);

  if (msg_bytes < AEZ_BYTES) // E(Kmac1[i], M)
  {
    memcpy(tmp, plaintext, sizeof(uint8_t) * msg_bytes);
    tmp[msg_bytes] = 1; 
    aez_blockcipher(mac, tmp, key->Kmac1[i], key, ENCRYPT, 10); 
  }

  else if (msg_bytes == AEZ_BYTES) // E(Kmac[i], M)
  {
    aez_blockcipher(mac, plaintext, key->Kmac[i], key, ENCRYPT, 10); 
  }

  else if ((msg_bytes % 16) == 0) // E(Kmac[i], M0 ^ AHash(K, M1 ... Mm)) 
  {
    aez_ahash(tmp, plaintext + AEZ_BYTES, msg_bytes - AEZ_BYTES, key); 
    XOR_BLOCK((uint32_t *)tmp, (uint32_t *)plaintext); 
    aez_blockcipher(mac, tmp, key->Kmac[i], key, ENCRYPT, 10); 
  }

  else // E(Kmac1[i], M0 ^ AHash(K, M1 ... Mm)) 
  {
    aez_ahash(tmp, plaintext + AEZ_BYTES, msg_bytes - AEZ_BYTES, key); 
    XOR_BLOCK((uint32_t *)tmp, (uint32_t *)plaintext); 
    aez_blockcipher(mac, tmp, key->Kmac1[i], key, ENCRYPT, 10); 
  }
}


/*
 * Ahash - a Wegmen-Carter style universal hash function based on 
 * a 4-round, non-invertible variant of AES.  
 */ 
void aez_ahash(uint8_t *hash, 
               const uint8_t *plaintext,
               size_t msg_bytes, 
               aez_keyvector_t *key)
{
  aez_reset_variant(key); 

  int j=1; 
  aez_block_t Khash;
  uint8_t tmp [AEZ_BYTES];
  ZERO_BLOCK((uint32_t *)hash);

  /* Apply AES4 to each block and XOR them together. */ 
  while (msg_bytes >= AEZ_BYTES)
  {
    aez_variant(Khash, key, (j + 7)/8, (j - 1) % 8, 0, 4); 
    aez_blockcipher(tmp, plaintext, Khash, key, ENCRYPT, 4); 
    XOR_BLOCK((uint32_t *)hash, (uint32_t *)tmp); 
    msg_bytes -= AEZ_BYTES; 
    plaintext += AEZ_BYTES; 
    j ++; 
  }
  
  /* Pad last block */ 
  if (msg_bytes) 
  {
    aez_variant(Khash, key, (j + 7)/8, (j - 1) % 8, 0, 4); 
    ZERO_BLOCK((uint32_t *)tmp); 
    memcpy(tmp, plaintext, sizeof(uint8_t) * msg_bytes);
    tmp[msg_bytes] = 0x80; 
    aez_blockcipher(tmp, tmp, Khash, key, ENCRYPT, 4);  
    XOR_BLOCK((uint32_t *)hash, (uint32_t *)tmp); 
  }

  aez_reset_variant(key); 
}
