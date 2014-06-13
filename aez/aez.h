
#ifndef AEZ_H
#define AEZ_H

#include "../portable.h"
#include <stdint.h>
#include <stdlib.h>

#define AEZ_BITS  128
#define AEZ_BYTES 16
#define AEZ_WORDS 4 

#define CP_BLOCK(dst, src) \
  { ((uint32_t *)dst)[0] = ((uint32_t *)src)[0]; \
    ((uint32_t *)dst)[1] = ((uint32_t *)src)[1]; \
    ((uint32_t *)dst)[2] = ((uint32_t *)src)[2]; \
    ((uint32_t *)dst)[3] = ((uint32_t *)src)[3]; } 
  //memcpy((dst), (src), sizeof(uint32_t) * AEZ_WORDS); 

#define XOR_BLOCK(dst, src) \
  { ((uint32_t *)dst)[0] ^= ((uint32_t *)src)[0]; \
    ((uint32_t *)dst)[1] ^= ((uint32_t *)src)[1]; \
    ((uint32_t *)dst)[2] ^= ((uint32_t *)src)[2]; \
    ((uint32_t *)dst)[3] ^= ((uint32_t *)src)[3]; }  

#define ZERO_BLOCK(dst) \
  { ((uint32_t *)dst)[0] = 0; \
    ((uint32_t *)dst)[1] = 0; \
    ((uint32_t *)dst)[2] = 0; \
    ((uint32_t *)dst)[3] = 0; }

#define BLOCK_MSB(X) (X[3] >> 31)


/*
 * Block types for key vectors. Careful - these are really of 
 * type (uint32_t*), i.e., sizeof(aez_block_t) == sizeof(void*). 
 * For this reason, we provide routines for instantiating them. 
 */ 
typedef uint32_t aez_block_t [AEZ_WORDS];

typedef aez_block_t aez_block4_t [5]; 

typedef aez_block_t aez_block10_t [11]; 

aez_block_t *aez_malloc_block(size_t msg_length); 
void aez_free_block(aez_block_t *blocks); 

aez_block4_t *aez_malloc_block4(size_t msg_length); 
void aez_free_block4(aez_block4_t *blocks); 

aez_block10_t *aez_malloc_block10(size_t msg_length); 
void aez_free_block10(aez_block10_t *blocks); 


/*
 * Key space for AEZ. 
 */

struct key_schedule {
  aez_block4_t  Kshort; 
  aez_block10_t Klong; 
};

/*
 * Intermediate data structure for key tweaking. A tweak of an AES round 
 * key K is defined by K ^ Offset, where Offset = (j * J) ^ (i * I) ^ (l * L).
 * The operator defines a recursive relation, instantiated as dot_inc(). We
 * precompute these values for valid (j, i, l) domain points. In the AEZ 
 * definition, j actually increments by doubling; in this case, it isn't 
 * necessary to precompute intermediate values. 
 */
struct tweak_state {
  aez_block_t Jinit, J, I [8], L [16];
};

typedef struct {

  /* Key schedules */ 
  struct key_schedule enc, dec; 

  /* Precomputed tweak vectors */ 
  struct tweak_state ts; 

  /* Offsets - tweaks don't change. */ 
  aez_block_t Kecb, // 11
              Kone, // 11
              Kff0; // 5 

  aez_block_t Kmac  [4], // 11
              Kmac1 [4]; // 11, Kmac'

} aez_keyvector_t; 



/*
 * Return status of AEZ routines. 
 */
typedef enum {
  aez_SUCCESS = 0,
  aez_INVALID_KEY = -1,
  aez_INVALID_ROUNDS = -2,
  aez_INVALID_MODE = -3,
  aez_NOT_IMPLEMENTED = -4,
  aez_MSG_LENGTH = -5
} aez_err_t; 


/*
 * Mode for key vector. AES sets up the key schedule
 * somewhat differently in the case of decryption. 
 */
typedef enum {
  ENCRYPT = 0, DECRYPT
} aez_mode_t;


/*
 * Key initialization routines. 
 */

void aez_init_keyvector(aez_keyvector_t *key, 
                        const uint8_t *K, 
                        aez_mode_t mode,
                        size_t msg_length);  

void aez_free_keyvector(aez_keyvector_t *key); 

/*
 * Basic tweaked blockcipher. 
 */

void aez_variant(aez_block_t offset, 
                 aez_keyvector_t *key,
                 int j, int i, int l, int k);

void aez_reset_variant(aez_keyvector_t *key); 

int aez_blockcipher(uint8_t *out, 
                    const uint8_t *in, 
                    const aez_block_t offset, 
                    aez_keyvector_t *key,
                    aez_mode_t mode,
                    int rounds); 

/*
 * Implemented in aez-mac.c
 */

void aez_print_block(const aez_block_t X, int margin);

void aez_amac(uint8_t *mac, 
              const uint8_t *plaintext, 
              size_t msg_bytes, 
              aez_keyvector_t *key, 
              int i); 

void aez_ahash(uint8_t *hash, 
               const uint8_t *plaintext,
               size_t msg_bytes, 
               aez_keyvector_t *key); 

/*
 * aez-cipher.c 
 */

int aez_encipher(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key); 

int aez_decipher(uint8_t *out, 
                 const uint8_t *in, 
                 const uint8_t *tag, 
                 size_t msg_bytes,
                 size_t tag_bytes, 
                 aez_keyvector_t *key); 

#endif // AEZ_H
