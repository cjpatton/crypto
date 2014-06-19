#include "aez.h"

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

int aez_extract(aez_keyvector_t *key, 
                const char *user_key, 
                size_t user_key_bytes) 
{
  return (int)aez_NOT_IMPLEMENTED;
}


