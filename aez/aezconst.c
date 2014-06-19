/* 
 * aezconstants.c - Generate AEZ constants for key extraction. 
 */ 

#include <stdio.h>
#include "aez.h"
#include "../cipher/aes.h"

int main() {

  uint8_t user_key [] = "AEZ-constant-AEZ"; 
  uint8_t plaintext [AEZ_BYTES]; 
  uint8_t ciphertext [AEZ_BYTES]; 
  
  aez_keyvector_t key; 
  aez_init_keyvector(&key, user_key); 

  int i; 
  for (i = 1; i <= 4; i++) {
    ZERO_BLOCK(plaintext); 
    *(uint32_t *)plaintext = i; /* TODO byte order */
    aes_encrypt(plaintext, ciphertext, (uint32_t *)key.enc.Klong, 10); 
    
    printf("CONST%d = ", i); 
    aez_print_block((uint32_t *)ciphertext, 0); 
  }
  
  aez_free_keyvector(&key); 

  return 0; 
}

