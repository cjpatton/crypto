#include "aez.h"
#include "../portable.h"
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* 
 * Local function declarations. 
 */

int encipher_ff0(uint8_t *ciphertext, 
                 const uint8_t *plaintext, 
                 const uint8_t *tag, 
                 const aez_keyvector_t *key);

int decipher_ff0(uint8_t *ciphertext, 
                 const uint8_t *plaintext, 
                 const uint8_t *tag, 
                 const aez_keyvector_t *key);
                     
int encipher_mem(uint8_t *ciphertext, 
                 const uint8_t *plaintext, 
                 const uint8_t *tag, 
                 size_t *msg_bytes,
                 const aez_keyvector_t *key);

int decipher_mem(uint8_t *ciphertext, 
                 const uint8_t *plaintext, 
                 const uint8_t *tag, 
                 const aez_keyvector_t *key);
                     


/*
 * tag_bytes == 32. 
 */
int aez_encipher(uint8_t *ciphertext, 
                 const uint8_t *plaintext, 
                 const uint8_t *tag, 
                 size_t *msg_bytes,
                 const aez_keyvector_t *key)
{
  if (msg_bytes < AEZ_BYTES) // FF0
    return (int)aez_NOT_IMPLEMENTED; 

  else if (msg_bytes == AEZ_BYTES)
  {
    uint8_t tweak [AEZ_BYTES]; 
    aez_amac(tweak, tag, 32, key, 3);
    // TODO ... 
  }

  else 
    return (int)aez_NOT_IMPLEMENTED; 

}

/*
 *
 */
int aez_decipher(uint8_t *plaintext, 
                 const uint8_t *ciphertext, 
                 const uint8_t *tag, 
                 const aez_keyvector_t *key)
{
  return (int)aez_NOT_IMPLEMENTED; 
}

