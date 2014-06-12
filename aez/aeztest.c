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
  XOR_BLOCK(key->enc.Klong[0], key->Kecb); 
  XOR_BLOCK(key->enc.Klong[10], key->Kecb); 
  aez_print_block(key->enc.Klong[0], 0); 
  for (i = 1; i < 11; i++)
    aez_print_block(key->enc.Klong[i], 5); 
  XOR_BLOCK(key->enc.Klong[0], key->Kecb); 
  XOR_BLOCK(key->enc.Klong[10], key->Kecb); 
  
  printf("\nKff0 ");
  XOR_BLOCK(key->enc.Kshort[0], key->Kff0); 
  aez_print_block(key->enc.Kshort[0], 0);
  for (i = 1; i < 5; i++)
    aez_print_block(key->enc.Kshort[i], 5);
  XOR_BLOCK(key->enc.Kshort[0], key->Kff0); 
  
  printf("\nKone "); 
  XOR_BLOCK(key->enc.Klong[0], key->Kone); 
  XOR_BLOCK(key->enc.Klong[10], key->Kone); 
  aez_print_block(key->enc.Klong[0], 0); 
  for (i = 1; i < 11; i++)
    aez_print_block(key->enc.Klong[i], 5); 
  XOR_BLOCK(key->enc.Klong[0], key->Kone); 
  XOR_BLOCK(key->enc.Klong[10], key->Kone); 

  for (j = 0; j < 4; j++) 
  {
    printf("\n Kmac[%d] ", j);
    XOR_BLOCK(key->enc.Klong[0], key->Kmac[j]); 
    XOR_BLOCK(key->enc.Klong[10], key->Kmac[j]); 
    aez_print_block(key->enc.Klong[0], 0); 
    for (i = 1; i < 11; i++)
      aez_print_block(key->enc.Klong[i], 9); 
    XOR_BLOCK(key->enc.Klong[0], key->Kmac[j]); 
    XOR_BLOCK(key->enc.Klong[10], key->Kmac[j]); 
  }
  
  for (j = 0; j < 4; j++) 
  {
    printf("\n Kmac'[%d] ", j);
    XOR_BLOCK(key->enc.Klong[0], key->Kmac1[j]); 
    XOR_BLOCK(key->enc.Klong[10], key->Kmac1[j]); 
    aez_print_block(key->enc.Klong[0], 0); 
    for (i = 1; i < 11; i++)
      aez_print_block(key->enc.Klong[i], 10); 
    XOR_BLOCK(key->enc.Klong[0], key->Kmac1[j]); 
    XOR_BLOCK(key->enc.Klong[10], key->Kmac1[j]); 
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
    XOR_BLOCK(key->enc.Kshort[0], key->Khash[j]); 
    aez_print_block(key->enc.Kshort[0], 0);
    for (i = 1; i < 5; i++)
      aez_print_block(key->enc.Kshort[i], 13);
    XOR_BLOCK(key->enc.Kshort[0], key->Khash[j]); 
  }
}

int main(int argc, const char **argv)
{
  /* Fake key to start. */ 
  uint8_t K [AEZ_BYTES]; 
  int i, bytes; 
  for (i = 0; i < AEZ_BYTES; i += 4)
  {
    *(uint32_t*)(&K[i]) = 1 << i; /* TODO byte order */ 
  }
  K[15] ^= 0x80;

  /* Initialize key vector. */ 
  aez_keyvector_t key; 
  aez_init_keyvector(&key, K, ENCRYPT, 64); 
  //dump_keys(&key); 
 
  /* Test cipher ... */
  uint8_t message [512]; 
//  uint8_t mac [16]; 
  uint8_t ciphertext [512]; 
  uint8_t plaintext [512]; 
  uint8_t tag [512]; 
  memset(plaintext, 0, 1024 * sizeof(uint8_t)); 
  memset(ciphertext, 0, 1024 * sizeof(uint8_t)); 
  memset(message, 0,1024 * sizeof(uint8_t)); 
  memset(tag, 0, 512 * sizeof(uint8_t)); 

  /* Test mac. */ 
//  printf("\nTest aez_amac() ... \n"); 
//  strcpy((char *)message, "0123456789abcdef000000000.00000000000000"); 
//  aez_amac(mac, message, strlen((char *)message), &key, 3); 
//  printf("Message: %s\n", message); 
//  printf("MAC:     "); 
//  dump_block((uint8_t *)mac, 0);
//  
//  strcpy((char *)message, "0123456789abcdef000000000000000000000000"); 
//  aez_amac(mac, message, strlen((char *)message), &key, 3); 
//  printf("Message: %s\n", message); 
//  printf("MAC:     "); 
//  dump_block((uint8_t *)mac, 0);

  /* Test encipher. */
  strcpy((char *)tag, "This is a tag, don't you know? AD, N."); 
  //strcpy((char *)message, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  strcpy((char *)message, "0123456789abcdef.stuff");
  bytes = aez_encipher(ciphertext, message, tag, strlen((char *)message), &key);  
  printf("bytes %d\n", bytes); 
  aez_decipher(plaintext, ciphertext, tag, bytes, &key); 
  
  printf("Message:    "); 
  aez_print_block((uint32_t *)message, 0);
  for (i = AEZ_BYTES; i <= bytes; i += AEZ_BYTES)
    aez_print_block((uint32_t *)&message[i], 12);
  
  printf("\nCiphertext: "); 
  aez_print_block((uint32_t *)ciphertext, 0);
  for (i = AEZ_BYTES; i <= bytes; i += AEZ_BYTES)
    aez_print_block((uint32_t *)&ciphertext[i], 12);
  
  printf("\nPlaintext:  "); 
  aez_print_block((uint32_t *)plaintext, 0);
  for (i = AEZ_BYTES; i <= bytes; i += AEZ_BYTES)
    aez_print_block((uint32_t *)&plaintext[i], 12);
  
  /* Destroy key vector. */ 
  aez_free_keyvector(&key); 
  
  

  return 0; 
}
