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
    tmp[msg_bytes] = 128; 
    aez_cipher(mac, tmp, key->Kmac1[i], key, ENCRYPT, 10); 
  }

  else if (msg_bytes == AEZ_BYTES) // E(Kmac[i], M)
  {
    aez_cipher(mac, plaintext, key->Kmac[i], key, ENCRYPT, 10); 
  }

  else if ((msg_bytes % 16) == 0) // E(Kmac[i], M0 ^ AHash(K, M1 ... Mm)) 
  {
    aez_ahash(tmp, plaintext + AEZ_BYTES, msg_bytes - AEZ_BYTES, key); 
    XOR_BLOCK((uint32_t *)tmp, (uint32_t *)plaintext); 
    aez_cipher(mac, tmp, key->Kmac[i], key, ENCRYPT, 10); 
  }

  else // E(Kmac1[i], M0 ^ AHash(K, M1 ... Mm)) 
  {
    aez_ahash(tmp, plaintext + AEZ_BYTES, msg_bytes - AEZ_BYTES, key); 
    XOR_BLOCK((uint32_t *)tmp, (uint32_t *)plaintext); 
    aez_cipher(mac, tmp, key->Kmac1[i], key, ENCRYPT, 10); 
  }
}


/*
 *
 */ 
void aez_ahash(uint8_t *hash, 
               const uint8_t *plaintext,
               size_t msg_bytes, 
               aez_keyvector_t *key)
{
  assert((msg_bytes / 16) < key->msg_length); 
  
  int i=0, j; 
  uint8_t tmp [AEZ_BYTES];
  ZERO_BLOCK((uint32_t *)hash);
 
  /* Apply AES4 to each block and XOR them together. */ 
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
    tmp[msg_bytes - j] = 128; 
    aez_cipher(tmp, tmp, key->Khash[i++], key, ENCRYPT, 4); // TODO Make sure this is ok. 
    XOR_BLOCK((uint32_t *)hash, (uint32_t *)tmp); 
  }
}
