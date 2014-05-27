
#ifndef AEZ_H
#define AEZ_H

#include <stdint.h>
#include <stdlib.h>

#define AEZ_BITS  128
#define AEZ_BYTES 16

typedef uint8_t aez_key_t [AEZ_BYTES];
/* Careful - this is really of type (uint8_t*), i.e., 
 * sizeof(aez_key_t) == sizeof(void*). */ 

typedef struct {

  size_t msg_length; // In 128-bit blocks. 

  aez_key_t Kecb, Kff0, Kone; 

  aez_key_t Kmac [4], 
            Kmac1 [4]; // Kmac'

  aez_key_t *K, *Khash;    // Initialize to max number of 128-bit blocks. 

} aez_keyvector_t; 


void aez_init_keyvector(aez_keyvector_t *key, const aez_key_t K, size_t msg_length);

void aez_free_keyvector(aez_keyvector_t *key); 

void aez_key_variant(aez_key_t Kout, const aez_key_t Kin,
                     int j, int i, int l, int k);

void aez_print_key(const aez_key_t K);

#endif // AEZ_H
