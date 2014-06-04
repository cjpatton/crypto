#include "aez.h"
#include "../portable.h"
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>

#define CP_BLOCK(dst, src) \
  dst[0] = src[0]; \
  dst[1] = src[1]; \
  dst[2] = src[2]; \
  dst[3] = src[3]; 

#define XOR_BLOCK(dst, src) \
  dst[0] ^= src[0]; \
  dst[1] ^= src[1]; \
  dst[2] ^= src[2]; \
  dst[3] ^= src[3]; 

#define ZERO_BLOCK(dst) \
  dst[0] = 0; \
  dst[1] = 0; \
  dst[2] = 0; \
  dst[3] = 0; 

#define BLOCK_MSB(X) (X[3] >> 31)


/*
 * Some local function declearations. 
 */

void dot2(aez_block_t X);
void dot_inc(aez_tweak_state_t *tweak_state, aez_block_t X, int n);
void dot_doubling(aez_tweak_state_t *tweak_state, aez_block_t X, int n);


/*
 * Allocate / free AEZ block arrays. 
 */

aez_block_t *aez_malloc_block(size_t msg_length)
{
  return malloc(msg_length * sizeof(uint32_t) * AEZ_WORDS); 
}

void aez_free_block(aez_block_t *blocks)
{
  free(blocks); 
}

aez_block4_t *aez_malloc_block4(size_t msg_length)
{
  return malloc(msg_length * 5 * sizeof(uint32_t) * AEZ_WORDS); 
}

void aez_free_block4(aez_block4_t *blocks)
{
  free(blocks); 
}

aez_block10_t *aez_malloc_block10(size_t msg_length)
{
  return malloc(msg_length * 11 * sizeof(uint32_t) * AEZ_WORDS); 
}

void aez_free_block10(aez_block10_t *blocks)
{
  free(blocks); 
}

/*
 * Initialize key vector.  
 */
void aez_init_keyvector(aez_keyvector_t *key, 
                        const uint8_t *K, 
                        aez_mode_t mode, 
                        size_t msg_length)
{
  aez_tweak_state_t tweak_state;
  int i, j, k;
  
  aez_init_tweak_state(&tweak_state, K, mode); 

  aez_key_variant(key->Kecb, &tweak_state, 0, 0, 1, 10); 
  aez_key_variant(key->Kff0, &tweak_state, 0, 0, 2, 4);
  aez_key_variant(key->Kone, &tweak_state, 0, 0, 3, 10);
  
  for (i = 0; i < 4; i++)
  {
    aez_key_variant(key->Kmac[i],  &tweak_state, 0, 0, i + 4, 10);
    aez_key_variant(key->Kmac1[i], &tweak_state, 0, 0, i + 9, 10);
  }

  key->msg_length = msg_length; 
  key->Khash = aez_malloc_block4(msg_length); 
  key->K =     aez_malloc_block(msg_length);
  for (i = 0; i < msg_length; i++)
  {
    j = 2 << (((i+1) / 8) + 1);
    k = i % 8; 
    aez_key_variant(&(key->K[i]),  &tweak_state, j, k, 0, 0);
    aez_key_variant(key->Khash[i], &tweak_state, j, k, 0, 4);
  }
}

void aez_free_keyvector(aez_keyvector_t *key)
{
  aez_free_block4(key->Khash); 
  aez_free_block(key->K); 
}


/*
 *
 */
void aez_init_tweak_state(aez_tweak_state_t *tweak_state, const uint8_t *K, aez_mode_t mode)
{
  aez_block_t tmp;

  /* Klong */ 
  switch(mode) 
  {
    case ENCRYPT: 
      aes_set_encrypt_key(K, (uint32_t *)tweak_state->Klong, 10);
      break;
    case DECRYPT: 
      aes_set_decrypt_key(K, (uint32_t *)tweak_state->Klong, 10);
      break;
  }

  /* Kshort */
  ZERO_BLOCK(tweak_state->Kshort[0]); 
  CP_BLOCK(tweak_state->Kshort[1], tweak_state->Klong[2]);
  CP_BLOCK(tweak_state->Kshort[2], tweak_state->Klong[5]);
  CP_BLOCK(tweak_state->Kshort[3], tweak_state->Klong[8]);
  ZERO_BLOCK(tweak_state->Kshort[4]); 

  /* I, J, L */ 
  ZERO_BLOCK(tmp); tmp[0] = 0; 
  aes_encrypt((const uint8_t *)tmp, 
              (uint8_t *)tweak_state->I, 
              (uint32_t *)tweak_state->Klong, 10); 

  tmp[0] = 1; 
  aes_encrypt((const uint8_t *)tmp, 
              (uint8_t *)tweak_state->J, 
              (uint32_t *)tweak_state->Klong, 10); 

  tmp[0] = 2;
  aes_encrypt((const uint8_t *)tmp, 
              (uint8_t *)tweak_state->L, 
              (uint32_t *)tweak_state->Klong, 10); 

  /* A zero-block. */ 
  ZERO_BLOCK(tweak_state->zero); 

//  int i;
//  printf("Klong\n"); 
//  for (i = 0; i < 11; i++) 
//    aez_print_block(tweak_state->Klong[i], 0); 
//
//  printf("Kshort\n"); 
//  for (i = 0; i < 5; i++) 
//    aez_print_block(tweak_state->Kshort[i], 0); 
//
//  printf("I "); 
//  aez_print_block(tweak_state->I, 0); 
//  printf("J "); 
//  aez_print_block(tweak_state->J, 0); 
//  printf("L "); 
//  aez_print_block(tweak_state->L, 0); 

}


/*
 * k is the number of AES rounds; j, i, and l are tweak_states. 
 */
int aez_key_variant(aez_block_t *Kout, 
                    const aez_tweak_state_t *tweak_state,
                    int j, int i, int l, int k)
{
  static aez_block_t offset, J, I, L;
  int a;

  CP_BLOCK(J, tweak_state->J); 
  CP_BLOCK(I, tweak_state->I); 
  CP_BLOCK(L, tweak_state->L); 
  dot_inc(tweak_state, j, J); 
  dot_inc(tweak_state, i, I); 
  dot_inc(tweak_state, l, L);
  CP_BLOCK(offset, J); 
  XOR_BLOCK(offset, I); 
  XOR_BLOCK(offset, L);

  //aez_print_block(offset, 0); 
  switch (k) 
  {
    case 0:
      CP_BLOCK(*Kout, offset);
      return (int)aez_SUCCESS; 
    case 4:
      for (a = 0; a < 5; a++)
        memcpy(Kout[a], tweak_state->Kshort[a], sizeof(uint32_t) * AEZ_WORDS); 
      XOR_BLOCK(Kout[0], offset); 
      return (int)aez_SUCCESS; 
    case 10:
      for (a = 0; a < 11; a++)
        memcpy(Kout[a], tweak_state->Klong[a], sizeof(uint32_t) * AEZ_WORDS); 
      XOR_BLOCK(Kout[0], offset); 
      XOR_BLOCK(Kout[10], offset); 
      return (int)aez_SUCCESS; 
  }
  return (int)aez_INVALID_KEY; 
}


void dot2(aez_block_t X)
{
  unsigned b = BLOCK_MSB(X);
  X[3] = (X[3] << 1) ^ (X[2] >> 31);
  X[2] = (X[2] << 1) ^ (X[1] >> 31);
  X[1] = (X[1] << 1) ^ (X[0] >> 31);
  X[0] = (X[0] << 1);
  if (b) 
    X[0] ^= 135;
}

/*
 * In psuedocode: 
 * def dot(X, n):
 *   if n == 0: return [0]
 *   elif n == 1: return X
 *   elif n == 2: return dot2(X)
 *   elif is_odd(n): return X ^ dot(X, n -1)
 *   elif is_even(n): return dot2(X, n/2)
 *
 * Precompute array of values for incrementing tweak (i ++) and 
 * doubling tweak (i *= 2). 
 * 
 */
void dot_inc(aez_tweak_state_t *tweak_state, aez_block_t X, int n)
{
  // TODO dynamic programming solution will be required. 
}

void dot_doubling(aez_tweak_state_t *tweak_state, aez_block_t X, int n)
{
  // TODO 
}


void aez_print_block(const aez_block_t X, int margin)
{
  int i;
  //uint8_t *p = X; 
  while (margin--)
    printf(" ");
  //for (i = AEZ_BYTES - 4; i >= 0; i -= 4)
  //  printf("0x%02x%02x%02x%02x ", p[i+3], p[i+2], p[i+1], p[i]); 
  for (i = AEZ_WORDS-1; i >= 0; i--) 
    printf("0x%08x ", ((uint32_t*)X)[i]); 
  printf("\n"); 
}
