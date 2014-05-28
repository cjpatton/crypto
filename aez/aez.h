
#ifndef AEZ_H
#define AEZ_H

#include <stdint.h>
#include <stdlib.h>

#define AEZ_BITS  128
#define AEZ_BYTES 16

/*
 * Block types for key vectors. Careful - these are really of 
 * type (uint8_t*), i.e., sizeof(aez_block_t) == sizeof(void*). 
 * For this reason, we provide routines for instantiating them. 
 */ 
typedef uint8_t aez_block_t [AEZ_BYTES];

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
typedef struct {

  size_t msg_length; // In 128-bit blocks. 

  aez_block_t Kecb[11], Kone [11], Kff0[5]; 

  aez_block_t Kmac  [4][11], 
              Kmac1 [4][11]; // Kmac'

  aez_block_t  *K;
  aez_block4_t *Khash; 

} aez_keyvector_t; 

void aez_init_keyvector(aez_keyvector_t *key, const aez_block_t K, size_t msg_length);

void aez_free_keyvector(aez_keyvector_t *key); 

void aez_key_variant(aez_block_t *Kout, const aez_block_t Kin,
                     int j, int i, int l, int k);

void aez_print_key(const aez_block_t K, int margin);

#endif // AEZ_H
