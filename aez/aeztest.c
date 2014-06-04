#include "aez.h"
#include <openssl/aes.h>
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>


void dump_block(const uint8_t *X, int margin)
{
  int i;
  while (margin--)
    printf(" ");
  for (i = AEZ_BYTES - 4; i >= 0; i -= 4)
    printf("0x%02x%02x%02x%02x ", X[i+3], X[i+2], X[i+1], X[i]); 
  printf("\n"); 
}

void dump_keys(aez_keyvector_t *key)
{
  int j, i;
  printf("Key schedules (AES round keys)\n\n"); 
  printf("Kecb "); 
  aez_print_block(key->Kecb[0], 0); 
  for (i = 1; i < 11; i++)
    aez_print_block(key->Kecb[i], 5); 
  
  printf("\nKff0 ");
  aez_print_block(key->Kff0[0], 0);
  for (i = 1; i < 5; i++)
    aez_print_block(key->Kff0[i], 5);
  
  printf("\nKone "); 
  aez_print_block(key->Kone[0], 0); 
  for (i = 1; i < 11; i++)
    aez_print_block(key->Kone[i], 5); 

  for (j = 0; j < 4; j++) 
  {
    printf("\n Kmac[%d] ", j);
    aez_print_block(key->Kmac[j][0], 0); 
    for (i = 1; i < 11; i++)
      aez_print_block(key->Kmac[j][i], 9); 
  }
  
  for (j = 0; j < 4; j++) 
  {
    printf("\n Kmac'[%d] ", j);
    aez_print_block(key->Kmac1[j][0], 0); 
    for (i = 1; i < 11; i++)
      aez_print_block(key->Kmac1[j][i], 10); 
  }

  printf("\n\nVectors\n\n"); 
  for (j = 0; j < key->msg_length; j++) 
  {
    printf(" K[%-4d] ", j);
    aez_print_block(key->K[j], 0); 
  }

  for (j = 0; j < key->msg_length; j++) 
  {
    printf("\n Khash[%-4d] ", j);
    aez_print_block(key->Khash[j][0], 0); 
    for (i = 1; i < 5; i++)
      aez_print_block(key->Khash[j][i], 13); 
  }
}

int main(int argc, const char **argv)
{
  /* Fake key to start. */ 
  uint8_t K [AEZ_BYTES]; 
  int i; 
  for (i = 0; i < AEZ_BYTES; i += 4)
  {
    *(uint32_t*)(&K[i]) = 1 << i;
  }
  K[15] ^= 0x80;

  /* Initialize key vector. */ 
  aez_keyvector_t encrypt_key, decrypt_key; 
  aez_init_keyvector(&encrypt_key, K, ENCRYPT, 32); 
  aez_init_keyvector(&decrypt_key, K, DECRYPT, 32); 
  
  dump_keys(&encrypt_key); 
  
  uint8_t message [32]; 
  uint8_t ciphertext [32]; 
  uint8_t plaintext [32]; 
  memset(message, 0, 32 * sizeof(uint8_t)); 
  strcpy((char*)message, "Find your bliss."); 
  memset(plaintext, 0, 32 * sizeof(uint8_t)); 
  memset(ciphertext, 0, 32 * sizeof(uint8_t)); 

  printf("Us ... \n"); 
  
  int rounds = 10; 
  aes_encrypt(message, ciphertext, (uint32_t *)(encrypt_key.Kone), rounds); 
  aes_decrypt(ciphertext, plaintext, (uint32_t *)(decrypt_key.Kone), rounds);
  
  printf("ciphertext: ");
  dump_block(ciphertext, 0);
  printf("plaintext:  "); 
  dump_block(plaintext, 0);
  printf("message:    %s\n", plaintext); 
  


  /* Destroy key vector. */ 
  aez_free_keyvector(&encrypt_key); 
  aez_free_keyvector(&decrypt_key); 

  

  printf("\n ... and them.\n");
  AES_KEY aes_key; 
  
  AES_set_encrypt_key(K, AEZ_BITS, &aes_key); 
  AES_encrypt(message, ciphertext, &aes_key); 
  AES_set_decrypt_key(K, AEZ_BITS, &aes_key); 
  AES_decrypt(ciphertext, plaintext, &aes_key);

  printf("ciphertext: ");
  dump_block(ciphertext, 0);
  printf("plaintext:  "); 
  dump_block(plaintext, 0);
  printf("message:    %s\n", plaintext); 

//  for (i = 0; i < 4; i++)
//  {
//    aez_print_key(key.Kmac[i]);
//    aez_print_key(key.Kmac1[i]);
//  }
//
//  for (i = 0; i < key.msg_length; i++)
//  {
//    aez_print_key(key.K[i]);
//    aez_print_key(key.Khash[i]);
//  }

  return 0; 
}
