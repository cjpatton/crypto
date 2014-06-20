#include "aez.h"
#include "../cipher/aes.h"
#include <string.h>

/*
 * Initialize constants. 
 *
 * TODO byte order 
 */

const aez_block_t aez_const1 = {0xd646a037, 0x12996f44, 0x5b000e23, 0x4345fca0};
const aez_block_t aez_const2 = {0x5275f58d, 0x932a3590, 0x6193cf1d, 0x8b4671b9};  
const aez_block_t aez_const3 = {0xbd68f1f2, 0x6d49838c, 0x658819d5, 0x56edba08}; 
const aez_block_t aez_const4 = {0x7219c43c, 0xd8d854f4, 0x049e54bf, 0x8d8e8389};  

int aez_encrypt(uint8_t *out, 
                const uint8_t *in,
                const uint8_t *nonce, 
                const uint8_t *data,
                size_t msg_bytes,
                size_t nonce_bytes,
                size_t data_bytes,
                aez_keyvector_t *key)
{
  return (int)aez_NOT_IMPLEMENTED;
}

int aez_decrypt(uint8_t *out, 
                const uint8_t *in,
                const uint8_t *nonce, 
                const uint8_t *data,
                size_t msg_bytes,
                size_t nonce_bytes,
                size_t data_bytes,
                aez_keyvector_t *key)
{
  return (int)aez_NOT_IMPLEMENTED;
}

int aez_format(uint8_t *tag, 
               const uint8_t *nonce,
               const uint8_t *data,
               size_t nonce_bytes,
               size_t data_bytes)
{
  return (int)aez_NOT_IMPLEMENTED;
}

/* 
 * TODO byte order of user_key
 */
int aez_extract(aez_keyvector_t *key, 
                const uint8_t *user_key, 
                size_t user_key_bytes) 
{
  int i;
  aez_keyvector_t key4; 
  aez_init_keyvector(&key4, (uint8_t *)aez_const4); 
  uint8_t K [AEZ_BYTES];  
  
  if (user_key_bytes == AEZ_BYTES) 
  {
    CP_BLOCK(K, user_key); 
    XOR_BLOCK(K, aez_const1); 
    aez_init_keyvector(key, K);  
    return (int)aez_SUCCESS; 
  }

  i = user_key_bytes % AEZ_BYTES; 
  if (i == 0) 
  {
    CP_BLOCK(K, &user_key[user_key_bytes - AEZ_BYTES]); 
    XOR_BLOCK(K, aez_const2); 
  }

  else 
  {
    ZERO_BLOCK(K); 
    memcpy(K, &user_key[user_key_bytes - i], i); 
    K[i] = 1;
    XOR_BLOCK(K, aez_const3); 
  }
  aes_encrypt(K, K, (uint32_t *)key4.enc.Klong, 10); 

  if (user_key_bytes > AEZ_BYTES) 
    for (i = 0; i < user_key_bytes - AEZ_BYTES; i += AEZ_BYTES) 
    {
      XOR_BLOCK(K, &user_key[i]); 
      aes_encrypt(K, K, (uint32_t *)key4.enc.Klong, 10); 
    }

  aez_init_keyvector(key, K);  
  return (int)aez_SUCCESS;
}


