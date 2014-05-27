/** 
 *
 * Testing, testing ... 
 *
 */

#include "chacha.h"
#include "../misc/keygen.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, const char **argv) 
{
  
  /* Generate a key. */ 
  uint32_t key[8]; 
  srand(1); 
  keygen (key, 8); 

  /* Nonce and block number. */ 
  uint64_t n=2, l=0; 

  char *message = malloc(64 * sizeof(char)); 
  char *plaintext = malloc(64 * sizeof(char)); 
  char *ciphertext = malloc(64 * sizeof(char)); 

  memset(message, 0, 64 * sizeof(char)); 
  if (argc == 2)
    strcpy(message, argv[1]);
  else
    strcpy(message, "Holy shit, this is a fancy block cipher."); 

  chacha_blockcipher(ciphertext, message, key, n, l); 
  chacha_blockcipher(plaintext, ciphertext, key, n, l); 
  
  printf("plaintext:\n");  chacha_disp_state((uint32_t *)plaintext);
  printf("ciphertext:\n"); chacha_disp_state((uint32_t *)ciphertext); 
  printf("message: %s\n", plaintext); 

  free(message);
  free(plaintext);
  free(ciphertext); 

  return 0; 
}
