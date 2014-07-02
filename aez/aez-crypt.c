/*
 * aez-crypt.c -- High level calls for the AEZ authenticated encryption 
 * mode, including user key extraction, encryption, and decryption. 
 * Encrypt, Decrypt, Format, Extract. 
 *
 * Christopher Patton <chrispatton@gmail.com>, June 2014.
 */

#include "aez.h"
#include "rijndael-alg-fst.h"
#include <string.h>
#include <stdio.h>

#define MAX(a, b) (a < b) ? b : a

/*
 * AEZ encryption. The length of the ciphertext (`out`) will 
 * be the length of the input message plus the length of the
 * authentication code (`auth_bytes`). `out` is expected to 
 * be at least max(msg_bytes + auth_bytes, 16), where 
 * auth_bytes <= 16. 
 */
int aez_encrypt(uint8_t *out, 
                const uint8_t *in,
                const uint8_t *nonce, 
                const uint8_t *data,
                size_t msg_bytes,
                size_t nonce_bytes,
                size_t data_bytes,
                size_t auth_bytes, 
                aez_keyvector_t *key)
{
  uint8_t *tag, *X = malloc(MAX(msg_bytes + auth_bytes, AEZ_BYTES)); 
  size_t tag_bytes = aez_format(&tag, nonce, data, 
                  nonce_bytes, data_bytes, auth_bytes); 
  memcpy(X, in, msg_bytes); 
  memset(X + msg_bytes, 0, auth_bytes);
  
  if (msg_bytes == 0)
    aez_amac(out, tag, tag_bytes, key, 4); 

  else
    aez_encipher(out, X, tag, msg_bytes + auth_bytes, tag_bytes, key); 

  free(X); 
  free(tag); 
  return msg_bytes + auth_bytes;
}


/*
 * AEZ decryption. `msg_bytes` should be the length of the enciphered 
 * message and message authenticaiton code (output of aez_encrypt()). 
 * If the MAC is correct, then the plaintext is copied to `out` (This  
 * is expected to be at least msg_bytes - auth_bytes long.) Otherwise
 * the plaintext is witheld and the function returns aez_REJECT. 
 */
int aez_decrypt(uint8_t *out, 
                const uint8_t *in,
                const uint8_t *nonce, 
                const uint8_t *data,
                size_t msg_bytes,
                size_t nonce_bytes,
                size_t data_bytes,
                size_t auth_bytes, 
                aez_keyvector_t *key)
{
  int i, res = msg_bytes - auth_bytes;  
  uint8_t *tag, *X = malloc(msg_bytes); 
  size_t tag_bytes = aez_format(&tag, nonce, data, 
                       nonce_bytes, data_bytes, auth_bytes); 
  
  if (msg_bytes == auth_bytes)
  {
    aez_amac(X, tag, tag_bytes, key, 4);
    for (i = 0; i < msg_bytes; i++)
      if (X[i] != in[i])
        res= (int)aez_REJECT; 
  }

  else 
  {
    aez_decipher(X, in, tag, msg_bytes, tag_bytes, key); 
    for (i = msg_bytes - auth_bytes; i < msg_bytes; i++)
      if (X[i] != 0)
        res = (int)aez_REJECT; 
  } 


  if (res != (int)aez_REJECT)
    memcpy(out, X, msg_bytes - auth_bytes); 
    
  free(X); 
  free(tag); 
  return res;
}


/*
 * Format nonce and additional data. Dynamically allocate an appropriate 
 * size buffer and assign it to `tag`; return the number of bytes in the 
 * buffer. (Caller should free `tag`.) This funciton is transcribed from 
 * Ted Krovetz' reference implementation of AEZ. 
 */
int aez_format(uint8_t **tag, 
               const uint8_t *nonce,
               const uint8_t *data,
               size_t nonce_bytes,
               size_t data_bytes,
               size_t auth_bytes)
{

  size_t tag_bytes;
  if (nonce_bytes <= 12) {
      uint8_t *res = malloc(data_bytes+16);
      memset(res,0,16);
      res[0] = (uint8_t)(nonce_bytes == 12 ? auth_bytes | 0x40 : auth_bytes);
      memcpy(res+4, nonce, nonce_bytes);
      if (nonce_bytes < 12) res[nonce_bytes+4] = 0x80;
      memcpy(res+16, data, data_bytes);
      tag_bytes = data_bytes+16;
      *tag = res;
  } else {
      unsigned pdata_bytes = 16 - (data_bytes % 16);
      uint8_t *res = malloc(5+nonce_bytes+data_bytes+pdata_bytes);
      res[0] = (uint8_t)(auth_bytes | 0x80);
      res[1] = res[2] = res[3] = 0;
      memcpy(res+4, nonce, 12);
      memcpy(res+16, data, data_bytes);
      res[16+data_bytes] = 0x80;
      memset(res+16+data_bytes+1,0,pdata_bytes-1);
      memcpy(res+16+data_bytes+pdata_bytes,nonce+12,nonce_bytes-12);
      res[4+nonce_bytes+data_bytes+pdata_bytes] = (uint8_t)nonce_bytes;
      tag_bytes = 5+nonce_bytes+data_bytes+pdata_bytes;
      *tag = res;
  }

  return tag_bytes;
}


/* 
 * Transform an arbitrary length user-supplied key into a 
 * pseudorandom 128-bit key suitable for AES. Initialize 
 * key vetor for AEZ encryption. 
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
  rijndaelKeySetupEnc((uint32_t *)K, aez_const, 128); 

  if (user_key_bytes == 16) 
  {
    rijndaelEncrypt((uint32_t *)K, 10, const1, const1); 
    CP_BLOCK(result, user_key); 
    XOR_BLOCK(result, const1);
  }
  else
  {
    rijndaelEncrypt((uint32_t *)K, 10, const2, const2); 
    rijndaelEncrypt((uint32_t *)K, 10, const3, const3); 
    rijndaelEncrypt((uint32_t *)K, 10, const4, const4); 
    rijndaelKeySetupEnc((uint32_t *)K, const4, 128); 
    ZERO_BLOCK(result);

    while (user_key_bytes > AEZ_BYTES) 
    {
      XOR_BLOCK(result, user_key); 
      rijndaelEncrypt((uint32_t *)K, 10, result, result); 
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
    rijndaelEncrypt((uint32_t *)K, 10, result, result); 
  }

  aez_free_block10(K); 
  aez_init_keyvector(key, result);  
  return (int)aez_SUCCESS;
}


