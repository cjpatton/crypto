#include "aez.h"
#include "../portable.h"
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>

/*
 * Some local function declearations. 
 */

void init_tweak_state(aez_keyvector_t *key,
                      const uint8_t *K);

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
                        const uint8_t *K)
{
  int i;
  
  /* Set up key schedules - Klong. */ 
  aes_set_encrypt_key(K, (uint32_t *)key->enc.Klong, 10); 
  aes_set_decrypt_key(K, (uint32_t *)key->dec.Klong, 10); 

  /* Kshort. */
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

  /* Initialize tweak state. */ 
  init_tweak_state(key, K); 

  /* Create key offsets (tweaks). Note that K and Khash are calculated 
   * on the fly in aez_{en,de}cipher() and aez_ahash() resp. */ 
  aez_variant(key->Kecb, key, 0, 0, 1, 10); 
  aez_variant(key->Kff0, key, 0, 0, 2, 4);
  aez_variant(key->Kone, key, 0, 0, 3, 10);
  
  for (i = 0; i < 4; i++)
  {
    aez_variant(key->Kmac[i],  key, 0, 0, i + 4, 10);
    aez_variant(key->Kmac1[i], key, 0, 0, i + 9, 10);
  }

}


/*
 * Initialize state for key tweaking (called by aez_init_keyvector()).  
 */
void init_tweak_state(aez_keyvector_t *key,
                      const uint8_t *K)
{
  int n; 
  aez_block_t tmp;

  /* I, J, L */ 
  ZERO_BLOCK(tmp); 
  
  /* j * J, where j iterates by doubling. Since this operation is 
   * closed, we don't need to compute intermediate values. */
  tmp[0] = 1; /* TODO byte order */ 
  aes_encrypt((const uint8_t *)tmp, 
              (uint8_t *)key->ts.J, 
              (uint32_t *)key->enc.Klong, 10); 

  CP_BLOCK(key->ts.Jinit, key->ts.J); 

  /* i * I, where i \in [0 .. 7]. Precompute all of these values.*/ 
  tmp[0] = 0; /* TODO byte order */ 
  ZERO_BLOCK(key->ts.I[0]); 
  aes_encrypt((const uint8_t *)tmp, 
              (uint8_t *)key->ts.I[1], 
              (uint32_t *)key->enc.Klong, 10); 
  for (n = 0; n < 8; n++)
  {
    dot_inc(key->ts.I, n);  
    //aez_print_block(key->ts.I[n], 0); 
  }
  
  /* l * L, where l \in [0 .. 16]. Precompute these values. */ 
  tmp[0] = 2; /* TODO byte order */ 
  ZERO_BLOCK(key->ts.L[0]); 
  aes_encrypt((const uint8_t *)tmp, 
              (uint8_t *)key->ts.L[1], 
              (uint32_t *)key->enc.Klong, 10); 
  for (n = 0; n < 16; n++)
  {
    dot_inc(key->ts.L, n);  
    //aez_print_block(key->ts.L[n], 0); 
  }

}


/*
 * k is the number of AES rounds; j, i, and l are tweaks. 
 */
void aez_variant(aez_block_t offset, 
                 aez_keyvector_t *key, 
                 int j, int i, int l, int k)
{
  if (j == 0) 
  {
    ZERO_BLOCK(offset); 
  } 
  else // Iterative doubling handled in aez_init_keyvector(). 
  {
    if (i == 0)
      dot2(key->ts.J); 
    CP_BLOCK(offset, key->ts.J); 
  }

  /* Precomputed. */ 
  XOR_BLOCK(offset, key->ts.I[i]); // I[j] = i * I.
  XOR_BLOCK(offset, key->ts.L[l]); // L[l] = l * L. 
  
  printf("Offset: "); aez_print_block((uint32_t *)offset, 0); 
}

void aez_reset_variant(aez_keyvector_t *key) 
{
  CP_BLOCK(key->ts.J, key->ts.Jinit); 
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


/*
 * Tweakable blockcipher, based on the OpenSSL implementation of 
 * AES128. The tweak is XOR'ed into the precomputed AES key 
 * schedule, then XOR'ed out. This routine supports 10-round 
 * schedules (standard AES) and 4-round schedules (AES4).
 *
 * TODO There's a lot of branching here that could be eliminated 
 *      by separating this into aez_aes_encrypt, aez_aes_decrypt, 
 *      and aez_aes4. 
 */
int aez_blockcipher(uint8_t *out, 
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


/*
 * Output a block. 
 *
 * TODO This should probably be removed in a production 
 *      verison of this program. 
 */
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


