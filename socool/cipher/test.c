
#include "aes_ni.h"
#include <string.h> 
#include <stdio.h>

void dumb_block(const byte *X)
{
  int i;
  for (i = 16 - 4; i >= 0; i -= 4)
    printf("0x%02x%02x%02x%02x ", X[i+3], X[i+2], X[i+1], X[i]); 
}


void test(const byte *msg, unsigned msg_bytes, 
          __m128i *key_sched, __m128i *key_sched_inv) 
{
  int i, bad = 0; 
  byte ciphertext[16], plaintext[16]; 
  ALIGN(16) byte buf [16]; 
  
  *(__m128i*)buf = _mm_setzero_si128();
  for (i = 0; i < msg_bytes; i++) 
    buf[i] = msg[i];

  aes_cipher(ciphertext, buf, key_sched, 0); 
  aes_cipher(plaintext, ciphertext, key_sched_inv, 1); 

  printf("Message:    ");
  for (i = 0; i < 16; i++)
  {
    putchar(plaintext[i]); 
    if (plaintext[i] != buf[i])
    {
      printf(" ... bad!");
      bad = 1; 
      break;
    }
  }
  printf("\nPlaintext:  "); 
  dumb_block(plaintext); 
  if (bad) 
    printf("mismatch!"); 
  printf("\nCiphertext: ");
  dumb_block(ciphertext);
  printf("\n"); 

}



int main() {
  ALIGN(16) byte user_key [] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}; 
  
  __m128i key = _mm_loadu_si128((__m128i*)user_key); 
  __m128i key_sched [11]; 
  __m128i key_sched_inv [11]; 
  
  /* Encipher schedule */ 
  aes_setup(key, key_sched); 

  /* Decipher schedule */
  aes_setup_inv(key, key_sched_inv, NULL); 

 
  byte message [] = "Hello!"; 
  unsigned msg_len = strlen((const char *)message); 

  test(message, msg_len, key_sched, key_sched_inv); 

  return 0; 
}
