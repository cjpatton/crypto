#include "aez.h"
#include <openssl/aes.h>
#include "../cipher/aes.h"
#include <stdio.h>
#include <string.h>

void unit_test(const uint8_t *message, const uint8_t *tag, 
               size_t msg_bytes, size_t tag_bytes, aez_keyvector_t *key);

void dump_block(const uint8_t *X, int margin);

void dump_keys(aez_keyvector_t *key);

int main(int argc, const char **argv)
{
  /* Fake key to start. */ 
  aez_keyvector_t key; 
  uint8_t message [1024]; 
  uint8_t tag [512]; 
  uint8_t K [AEZ_BYTES]; 
  int i; 
  for (i = 0; i < AEZ_BYTES; i += 4)
  {
    *(uint32_t*)(&K[i]) = 1 << i; /* TODO byte order */ 
  }
  K[15] ^= 0x80;

  /* Initialize key vector. */ 
  aez_init_keyvector(&key, K, ENCRYPT, 64); 
  //dump_keys(&key); 
 
  /* Enciphering tests. */
  memset(tag, 0, 512 * sizeof(uint8_t)); 
  strcpy((char *)tag, "Man, this is a super nice tag.");
  
  memset(message, 0, 1024 * sizeof(uint8_t)); 
  strcpy((char *)message, "0123456789abcdef");
  unit_test(message, tag, strlen((char *)message), strlen((char *)tag), &key); 

  memset(message, 0,1024 * sizeof(uint8_t)); 
  strcpy((char *)message, "0123456789abcdef.");
  unit_test(message, tag, strlen((char *)message), strlen((char *)tag), &key); 

  memset(message, 0,1024 * sizeof(uint8_t)); 
  strcpy((char *)message, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefstuff");
  unit_test(message, tag, strlen((char *)message), strlen((char *)tag), &key); 
  
  /* Destroy key vector. */ 
  aez_free_keyvector(&key); 
  
  

  return 0; 
}


void unit_test(const uint8_t *message, const uint8_t *tag, 
               size_t msg_bytes, size_t tag_bytes, aez_keyvector_t *key)
{
  static int test_no = 1; 
  int i, j;
  
  uint8_t *ciphertext = malloc(msg_bytes + AEZ_BYTES); 
  uint8_t *plaintext  = malloc(msg_bytes + AEZ_BYTES);  
  memset(plaintext, 0, msg_bytes + AEZ_BYTES); 
  memset(ciphertext, 0, msg_bytes + AEZ_BYTES); 
  
  printf("Test #%d (%d bytes)\n", test_no++, (int)msg_bytes); 
  
  int bytes = aez_encipher(ciphertext, message, tag, msg_bytes, tag_bytes, key);  
  
  aez_decipher(plaintext, ciphertext, tag, 
               bytes, tag_bytes, key); 
  
  printf(" Message:    "); 
  aez_print_block((uint32_t *)message, 0);
  for (i = AEZ_BYTES; i <= bytes; i += AEZ_BYTES)
    aez_print_block((uint32_t *)&message[i], 13);
  
  printf("\n Ciphertext: "); 
  aez_print_block((uint32_t *)ciphertext, 0);
  for (i = AEZ_BYTES; i <= bytes; i += AEZ_BYTES)
    aez_print_block((uint32_t *)&ciphertext[i], 13);

  //plaintext[4] = 'q';
  for (j = 0; j < bytes; j++)
  {
    if (plaintext[j] != message[j])
    {
      printf("\n Message-plaintext mismatch!\n"); 
      printf(" Plaintext:  "); 
      aez_print_block((uint32_t *)plaintext, 0);
      for (i = AEZ_BYTES; i <= bytes; i += AEZ_BYTES)
        aez_print_block((uint32_t *)&plaintext[i], 13);
      printf("\n"); 
      break;
    }
  }

  if (j == bytes)
    printf("\n No problem.\n\n"); 

  free(ciphertext);
  free(plaintext); 
}

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
