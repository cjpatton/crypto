#include "aez.h"
#include "../portable.h"
#include <stdio.h>
#include <string.h>


/*
 * Allocate / free AEZ block arrays. 
 */

aez_block_t *aez_malloc_block(size_t msg_length)
{
  return malloc(msg_length * sizeof(uint8_t) * AEZ_BYTES); 
}

void aez_free_block(aez_block_t *blocks)
{
  free(blocks); 
}

aez_block4_t *aez_malloc_block4(size_t msg_length)
{
  return malloc(msg_length * 5 * sizeof(uint8_t) * AEZ_BYTES); 
}

void aez_free_block4(aez_block4_t *blocks)
{
  free(blocks); 
}

aez_block10_t *aez_malloc_block10(size_t msg_length)
{
  return malloc(msg_length * 11 * sizeof(uint8_t) * AEZ_BYTES); 
}

void aez_free_block10(aez_block10_t *blocks)
{
  free(blocks); 
}

/*
 * Initialize key vector.  
 */
void aez_init_keyvector(aez_keyvector_t *key, const aez_block_t K, size_t msg_length)
{
  int i, j, k;
  
  aez_key_variant(key->Kecb, K, 0, 0, 1, 10); 
  aez_key_variant(key->Kff0, K, 0, 0, 2, 4);
  aez_key_variant(key->Kone, K, 0, 0, 3, 10);
  
  for (i = 0; i < 4; i++)
  {
    aez_key_variant(key->Kmac[i],  K, 0, 0, i + 4, 10);
    aez_key_variant(key->Kmac1[i], K, 0, 0, i + 9, 10);
  }

  key->msg_length = msg_length; 
  key->Khash = aez_malloc_block4(msg_length); 
  key->K =     aez_malloc_block(msg_length);
  for (i = 0; i < msg_length; i++)
  {
    j = 2 << (((i+1) / 8) + 1);
    k = i % 8; 
    aez_key_variant(&(key->K[i]),  K, j, k, 0, 0);
    aez_key_variant(key->Khash[i], K, j, k, 0, 4);
  }
}

void aez_free_keyvector(aez_keyvector_t *key)
{
  aez_free_block4(key->Khash); 
  aez_free_block(key->K); 
}

/*
 * k is the number of AES rounds; j, i, and l are tweaks. 
 */
void aez_key_variant(aez_block_t *Kout, const aez_block_t Kin, 
                     int j, int i, int l, int k)
{
  // TODO
  int a; 
  for (a = 0; a <= k; a++)
    memcpy(Kout[a], Kin, sizeof(uint8_t) * AEZ_BYTES);
}


void aez_print_block(const aez_block_t X, int margin)
{
  int i;
  while (margin--)
    printf(" "); 

  for (i = AEZ_BYTES - 4; i >= 0; i -= 4)
  { 
    printf("0x%02x%02x%02x%02x ", X[i+3], X[i+2], X[i+1], X[i]); 
  }
  //for (i = AEZ_WORDS-1; i >= 0; i--) 
  //  printf("0x%08x ", ((uint32_t*)X)[i]); 
  printf("\n"); 
}
