#include "aez.h"
#include "../cipher/aes.h"
#include <string.h>
#include <stdio.h>

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
 * 
 */
int aez_extract(aez_keyvector_t *key, 
                const uint8_t *user_key, 
                size_t user_key_bytes) 
{
  
  uint8_t result [AEZ_BYTES], tmp [AEZ_BYTES],
          const1 [AEZ_BYTES], const2[AEZ_BYTES], 
          const3 [AEZ_BYTES], const4[AEZ_BYTES]; 

  uint8_t aez_const [] = "AEZ-Constant-AEZ";
  
  memset(const1, 0, AEZ_BYTES); const1[15] = 0x01; 
  memset(const2, 0, AEZ_BYTES); const2[15] = 0x02; 
  memset(const3, 0, AEZ_BYTES); const3[15] = 0x03; 
  memset(const4, 0, AEZ_BYTES); const4[15] = 0x04; 

  aez_block10_t *K = aez_malloc_block10(1);
  aes_set_encrypt_key(aez_const, (uint32_t *)K, 10);
  
  if (user_key_bytes == 16) 
  {
    aes_encrypt(const1, const1, (uint32_t *)K, 10); 
    CP_BLOCK(result, user_key); 
    XOR_BLOCK(result, const1);
  }
  else
  {
    aes_encrypt(const2, const2, (uint32_t *)K, 10); 
    aes_encrypt(const3, const3, (uint32_t *)K, 10); 
    aes_encrypt(const4, const4, (uint32_t *)K, 10); 
    aes_set_encrypt_key(const4, (uint32_t *)K, 10);
    ZERO_BLOCK(result);

    while (user_key_bytes > AEZ_BYTES) 
    {
      XOR_BLOCK(result, user_key); 
      aes_encrypt(result, result, (uint32_t *)K, 10); 
      user_key += AEZ_BYTES;
      user_key_bytes -= AEZ_BYTES; 
    }

    if (user_key_bytes < AEZ_BYTES) // Pad fragmented last block
    {
      ZERO_BLOCK(tmp); 
      memcpy(tmp, user_key, user_key_bytes); 
      tmp[user_key_bytes] = 0x80; 
      XOR_BLOCK(tmp, const3); 
    }

    else
    {
      CP_BLOCK(tmp, user_key); 
      XOR_BLOCK(tmp, const2); 
    }
    
    XOR_BLOCK(result, tmp); 
    aes_encrypt(result, result, (uint32_t *)K, 10);   
  }

  aez_free_block10(K); 
  printf("result: "); aez_print_block((uint32_t *)result, 0); 
  aez_init_keyvector(key, result);  
  return (int)aez_SUCCESS;
}


