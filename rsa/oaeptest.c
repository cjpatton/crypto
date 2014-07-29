/**
 * Testing, testing ... 
 *
 */ 

#include "oaep.h"
#include "rsa.h"
#include "../hash/sha1.h"
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main(int argc, const char **argv)
{
  rsa_private_t sk; 
  rsa_public_t pk; 

  rsa_read_private(&sk, "fella"); 
  rsa_read_public(&pk, "fella.pub"); 
  
  int i, err; 
  size_t lCipher, lMsg, lN = pk.n / 8; 
  char  message[] = "Dear Barack Obama, my name is julie and I would like to be the president someday, of the united states of america someday. Given that you are the current president,o",
        message2[] = "Everything is going to be fine. ",
       *plaintext = malloc(4096 * sizeof(char)),
       *ciphertext = malloc(4096 * sizeof(char));

  err = oaep_encrypt(ciphertext, message2, &lCipher, strlen(message2), 17, &pk);
  switch (err)
  {
    
    case (oaepMsgLength):
      fprintf(stderr, "oaeptest: input message too long.\n");
      break;

    case (oaepModulusTooSmall):
      fprintf(stderr, "oaeptest: encryption error: modulus too small.\n");
      break;
    
    default:
      for (i = 0; i < lCipher; i++)
        printf("%02x ", (unsigned char)ciphertext[i]); 
      printf("\n");
      break;

  }

  if (!err)
  {
    err = oaep_decrypt(plaintext, ciphertext, &lMsg, lCipher, 17, &sk);
    switch(err)
    {
      case oaepLabelMismatch: 
        fprintf(stderr, "oaeptest: error: label mismatch!\n"); 
        break;
      case oaepCipherLength: 
        fprintf(stderr, "oaeptest: error: cipher length!\n"); 
        break;
      case (oaepModulusTooSmall):
        fprintf(stderr, "oaeptest: encryption error: modulus too small.\n");
        break;
      default:
          plaintext[lMsg] = '\0';
          printf("%s\n", plaintext); 
    }
  }

  free(plaintext); 
  free(ciphertext); 
  rsa_free_private(&sk); 
  rsa_free_public(&pk); 

  return 0;
}
