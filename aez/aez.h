
#ifndef AEZ_H
#define AEZ_H

#include "../portable.h"
#include <stdint.h>
#include <stdlib.h>

#define AEZ_BITS  128
#define AEZ_BYTES 16
#define AEZ_WORDS 4 

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
typedef struct {

  size_t msg_length; // In 128-bit blocks. 

  aez_block_t Kecb[11], Kone [11], Kff0[5]; 

  aez_block_t Kmac  [4][11], 
              Kmac1 [4][11]; // Kmac'

  aez_block_t  *K;
  aez_block4_t *Khash; 

} aez_keyvector_t; 


/*
 * Intermediate data structure for key tweak_stateing. 
 */
typedef struct {
  aez_block_t I, J, L, zero;
  aez_block10_t Klong; 
  aez_block4_t  Kshort; 
} aez_tweak_state_t;


typedef enum {
  aez_SUCCESS, 
  aez_INVALID_KEY
} aez_err_t; 


/*
 * Mode for key vector. AES sets up the key schedule
 * somewhat differently in the case of decryption. 
 */
typedef enum {
  ENCRYPT = 0, DECRYPT
} aez_mode_t;



void aez_init_keyvector(aez_keyvector_t *key, 
                        const uint8_t *K, 
                        aez_mode_t mode,
                        size_t msg_length);  

void aez_free_keyvector(aez_keyvector_t *key); 

void aez_init_tweak_state(aez_tweak_state_t *tweak_state, const uint8_t *K, aez_mode_t mode); 

int aez_key_variant(aez_block_t *Kout, 
                    const aez_tweak_state_t *tweak_state,
                    int j, int i, int l, int k);

void aez_print_block(const aez_block_t X, int margin);

#endif // AEZ_H
