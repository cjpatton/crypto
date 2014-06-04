#include "aez.h"
#include "../portable.h"
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>

/*
 * Some local function declearations. 
 */

void dot2(aez_block_t X);
void dot_inc(aez_block_t *Xs, int n);


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
  aez_tweak_state_t *tweak_state = malloc(sizeof(aez_tweak_state_t)); ;
  int n, i, j = 0;
  
  aez_init_tweak_state(tweak_state, key, K, mode); 

  aez_key_variant(key->Kecb, tweak_state, 0, 0, 1, 10); 
  aez_key_variant(key->Kff0, tweak_state, 0, 0, 2, 4);
  aez_key_variant(key->Kone, tweak_state, 0, 0, 3, 10);
  
  for (i = 0; i < 4; i++)
  {
    aez_key_variant(key->Kmac[i],  tweak_state, 0, 0, i + 4, 10);
    aez_key_variant(key->Kmac1[i], tweak_state, 0, 0, i + 9, 10);
  }

  key->msg_length = msg_length; 
  key->Khash = aez_malloc_block(msg_length); 
  key->K =     aez_malloc_block(msg_length);
  for (n = 0; n < msg_length; n++) 
  {
    i = (n % 8);
    if (i == 0) // iterate by doubling
      dot2(tweak_state->J);

    ++j; // Bit of a nothing variable.  
    aez_key_variant(key->K[n],  tweak_state, j, i, 0, 0);
    aez_key_variant(key->Khash[n], tweak_state, j, i, 0, 4);
  }

  free(tweak_state); 
}


/*
 * Free key vector. 
 */
void aez_free_keyvector(aez_keyvector_t *key)
{
  aez_free_block(key->Khash); 
  aez_free_block(key->K); 
}


/*
 * Initialize state for key tweaking (called by aez_init_keyvector()).  
 */
void aez_init_tweak_state(aez_tweak_state_t *tweak_state, 
                          aez_keyvector_t *key,
                          const uint8_t *K, 
                          aez_mode_t mode)
{
  int n; 
  aez_block_t tmp;

  /* Klong */ 
  aes_set_encrypt_key(K, (uint32_t *)key->enc.Klong, 10); 
  
  aes_set_decrypt_key(K, (uint32_t *)key->dec.Klong, 10); 

  /* Kshort */
  ZERO_BLOCK(key->enc.Kshort[0]); 
  CP_BLOCK(key->enc.Kshort[1], key->enc.Klong[2]);
  CP_BLOCK(key->enc.Kshort[2], key->enc.Klong[5]);
  CP_BLOCK(key->enc.Kshort[3], key->enc.Klong[8]);
  ZERO_BLOCK(key->enc.Kshort[4]); 
  
  ZERO_BLOCK(key->dec.Kshort[0]); 
  CP_BLOCK(key->dec.Kshort[1], key->dec.Klong[2]);
  CP_BLOCK(key->dec.Kshort[2], key->dec.Klong[5]);
  CP_BLOCK(key->dec.Kshort[3], key->dec.Klong[8]);
  ZERO_BLOCK(key->dec.Kshort[4]); 

  /* I, J, L */ 
  ZERO_BLOCK(tmp); 
  
  /* j * J, where j iterates by doubling. Since this operation is 
   * closed, we don't need to compute intermediate values. */ 
  tmp[0] = 1; 
  aes_encrypt((const uint8_t *)tmp, 
              (uint8_t *)tweak_state->J, 
              (uint32_t *)key->enc.Klong, 10); 
  
  /* i * I, where i \in [0 .. 7]. Precompute all of these values.*/ 
  tmp[0] = 0; 
  ZERO_BLOCK(tweak_state->I[0]); 
  aes_encrypt((const uint8_t *)tmp, 
              (uint8_t *)tweak_state->I[1], 
              (uint32_t *)key->enc.Klong, 10); 
  for (n = 0; n < 8; n++)
  {
    dot_inc(tweak_state->I, n);  
    //aez_print_block(tweak_state->I[n], 0); 
  }
  
  /* l * L, where l \in [0 .. 16]. Precompute these values. */ 
  tmp[0] = 2;
  ZERO_BLOCK(tweak_state->L[0]); 
  aes_encrypt((const uint8_t *)tmp, 
              (uint8_t *)tweak_state->L[1], 
              (uint32_t *)key->enc.Klong, 10); 
  for (n = 0; n < 16; n++)
  {
    dot_inc(tweak_state->L, n);  
    //aez_print_block(tweak_state->L[n], 0); 
  }

}


/*
 * k is the number of AES rounds; j, i, and l are tweaks. 
 */
int aez_key_variant(aez_block_t offset, 
                    const aez_tweak_state_t *tweak_state,
                    int j, int i, int l, int k)
{
  if (j == 0) {
    ZERO_BLOCK(offset); 
  } else { // Iterative doubling handled in aez_init_keyvector(). 
    CP_BLOCK(offset, tweak_state->J); 
  }

  XOR_BLOCK(offset, tweak_state->I[i]); // I[j] = i * J.
  
  XOR_BLOCK(offset, tweak_state->L[l]); // L[l] = l * L. 

  switch (k) 
  {
    case 0:
      return (int)aez_SUCCESS; 
    case 4:
      return (int)aez_SUCCESS; 
    case 10:
      return (int)aez_SUCCESS; 
  }
  return (int)aez_INVALID_KEY; 
}


/*
 * 2 * X dot operation 
 */
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
 * Precompute array of values for incrementing tweak (i ++) 
 */
void dot_inc(aez_block_t *Xs, int n)
{
  if (n == 0) 
    ;
  
  else if (n == 1)
    ; 

  else if (n == 2)
  {
    CP_BLOCK(Xs[2], Xs[1]);
    dot2(Xs[2]);
  }

  else if ((n % 2) == 1) // odd
  {
    CP_BLOCK(Xs[n], Xs[n-1]); 
    XOR_BLOCK(Xs[n], Xs[1]);    
  }

  else // even
  {
    CP_BLOCK(Xs[n], Xs[n/2]);
    dot2(Xs[n]); 
  }
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




int aez_cipher(uint8_t *out, 
               const uint8_t *in, 
               const aez_block_t offset, 
               aez_keyvector_t *key,
               aez_mode_t mode,
               int rounds)
{
  
  void (*cipher)(const uint8_t *, uint8_t *, const aes_key_t *, int); 
  struct key_schedule *sched; 

  if (mode == ENCRYPT)
  {
    cipher = aes_encrypt;
    sched = &(key->enc);
  }
  else if (mode == DECRYPT)
  {
    cipher = aes_decrypt; 
    sched = &(key->dec);
  }
  else
    return (int)aez_INVALID_MODE; 

  if (rounds == 10)
  {
    XOR_BLOCK(sched->Klong[0], offset);    
    XOR_BLOCK(sched->Klong[10], offset);    
    cipher(in, out, (uint32_t *)sched->Klong, rounds);
    XOR_BLOCK(sched->Klong[0], offset);    
    XOR_BLOCK(sched->Klong[10], offset);    
  }

  else if (rounds == 4)
  {
    XOR_BLOCK(sched->Kshort[0], offset); 
    cipher(in, out, (uint32_t *)sched->Kshort, rounds);
    XOR_BLOCK(sched->Kshort[0], offset); 
  }

  else
    return (int)aez_INVALID_ROUNDS; 

  return (int)aez_SUCCESS;
}
