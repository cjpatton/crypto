#include "aez.h"
#include <openssl/aes.h>
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>


void dump_keys(aez_keyvector_t *key)
{
  int j, i;
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
  aez_block_t K; 
  int i; 
  for (i = 0; i < AEZ_BYTES; i += 4)
  {
    *(uint32_t*)(&K[i]) = 1 << i;
  }

  /* Initialize key vector. */ 
  aez_keyvector_t key; 
  aez_init_keyvector(&key, K, 1 << 2); 
  
  //dump_keys(&key); 
  
  /* Destroy key vector. */ 
  aez_free_keyvector(&key); 


  /* Test AES. */ 
  uint8_t message [32]; 
  uint8_t ciphertext [32]; 
  uint8_t plaintext [32]; 
  memset(message, 0, 32 * sizeof(uint8_t)); 
  strcpy((char*)message, "Find your bliss."); 
  memset(plaintext, 0, 32 * sizeof(uint8_t)); 
  memset(ciphertext, 0, 32 * sizeof(uint8_t)); 

  printf("Us ... \n"); 
  aes_key_t aes_key2; 
  
  aes_set_encrypt_key(K, 128, &aes_key2); 
  aes_encrypt(message, ciphertext, &aes_key2); 
  aes_set_decrypt_key(K, 128, &aes_key2); 
  
  aes_decrypt(ciphertext, plaintext, &aes_key2);
  printf("ciphertext: ");
  aez_print_block(ciphertext, 0);
  printf("plaintext:  "); 
  aez_print_block(plaintext, 0);
  printf("message:    %s\n", plaintext); 
  

  printf("\n ... and them.\n");
  AES_KEY aes_key; 
  
  AES_set_encrypt_key(K, 128, &aes_key); 
  AES_encrypt(message, ciphertext, &aes_key); 
  AES_set_decrypt_key(K, 128, &aes_key); 
  
  AES_decrypt(ciphertext, plaintext, &aes_key);
  printf("ciphertext: ");
  aez_print_block(ciphertext, 0);
  printf("plaintext:  "); 
  aez_print_block(plaintext, 0);
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
