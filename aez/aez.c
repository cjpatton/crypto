#include "aez.h"
#include "../misc/portable.h"
#include <stdio.h>
#include <string.h>

void aez_init_keyvector(aez_keyvector_t *key, const aez_key_t K, size_t msg_length)
{
  int i;
  
  aez_key_variant(key->Kecb, K, 0, 0, 1, 10); 
  aez_key_variant(key->Kff0, K, 0, 0, 2, 4);
  aez_key_variant(key->Kone, K, 0, 0, 3, 10);
  
  for (i = 0; i < 4; i++)
  {
    aez_key_variant(key->Kmac[i],  K, 0, 0, i + 4, 10);
    aez_key_variant(key->Kmac1[i], K, 0, 0, i + 9, 10);
  }

  key->msg_length = msg_length; 
  key->Khash = malloc(msg_length * sizeof(uint8_t) * AEZ_BYTES); 
  key->K = malloc(msg_length * sizeof(uint8_t) * AEZ_BYTES); 
  for (i = 0; i < msg_length; i++)
  {
    aez_key_variant(key->K[i], K, 2 << (((i+1) / 8) + 1), i % 8, 0, 0);
    aez_key_variant(key->Khash[i], K, 2 << (((i+1) / 8) + 1), i % 8, 0, 4);
  }

}

void aez_free_keyvector(aez_keyvector_t *key)
{
  free(key->Khash); 
}

void aez_key_variant(aez_key_t Kout, const aez_key_t Kin, 
                     int j, int i, int l, int k)
{
  memcpy(Kout, Kin, sizeof(uint8_t) * AEZ_BYTES);
}


void aez_print_key(const aez_key_t K)
{
  int i;
  for (i = AEZ_BYTES - 4; i >= 0; i -= 4)
  {
    printf("0x%02x%02x%02x%02x ", K[i+3], K[i+2], K[i+1], K[i]); 
    //printf("0x%08x ", *(uint32_t*)(&K[i])); 
  }
  printf("\n"); 
}
