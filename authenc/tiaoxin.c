/* 
 * tiaoxin.c -- Tiaoxin-346, a Caesar submission. 
 * TODO Processing of additional data. 
 */

#include <stdint.h>
#include <wmmintrin.h>
#include <tmmintrin.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#define ALIGN(n) __attribute__ ((aligned(n)))

typedef unsigned char Byte; 

ALIGN(16) const Byte Z0 [] = {0x42, 0x8a, 0x2f, 0x98,
                              0xd7, 0x28, 0xae, 0x22, 
                              0x71, 0x37, 0x44, 0x91,
                              0x23, 0xef, 0x65, 0xcd}; 

ALIGN(16) const Byte Z1 [] = {0xb5, 0xc0, 0xfb, 0xcf,
                              0xec, 0x4d, 0x3b, 0x2f,
                              0xe9, 0xb5, 0xdb, 0xa5,
                              0x81, 0x89, 0xdb, 0xbc}; 

typedef struct {

  __m128i T3[3], T4[4], T6[6]; 

} TiaoxinState; 


void disp(const TiaoxinState *state)
{
  ALIGN(16) Byte buff [16]; 

  printf("+---- Tiaoxin-346 state -------------------+\n"); 

  for (int i = 0; i < 3; i++)
  {
    _mm_store_si128((__m128i*)buff, state->T3[i]); 
    printf("| T3[%d] = ", i); 
    for (int j = 0; j < 16; j++)
    {
      printf("%02x", buff[j]); 
    }
    printf(" |\n"); 
  }
  printf("+------------------------------------------+\n"); 
  
  for (int i = 0; i < 4; i++)
  {
    _mm_store_si128((__m128i*)buff, state->T4[i]); 
    printf("| T4[%d] = ", i); 
    for (int j = 0; j < 16; j++)
    {
      printf("%02x", buff[j]); 
    }
    printf(" |\n"); 
  }
  printf("+------------------------------------------+\n"); 
  
  for (int i = 0; i < 6; i++)
  {
    _mm_store_si128((__m128i*)buff, state->T6[i]); 
    printf("| T6[%d] = ", i); 
    for (int j = 0; j < 16; j++)
    {
      printf("%02x", buff[j]); 
    }
    printf(" |\n"); 
  }

  printf("+------------------------------------------+\n"); 
}


void update(TiaoxinState *state, __m128i M0, __m128i M1, __m128i M2)
{
  __m128i tmp [6]; 
  __m128i *T; 

  T = state->T3; 
  
  tmp[0] = _mm_aesenc_si128(T[2], T[0]) ^ M0; 
  tmp[1] = _mm_aesenc_si128(T[0], *(__m128i*)Z0); 
  tmp[2] = T[1]; 

  T[0] = tmp[0];
  T[1] = tmp[1];
  T[2] = tmp[2]; 
  
  T = state->T4; 
  
  tmp[0] = _mm_aesenc_si128(T[3], T[0]) ^ M1; 
  tmp[1] = _mm_aesenc_si128(T[0], *(__m128i*)Z0); 
  tmp[2] = T[1]; 
  tmp[3] = T[2]; 

  T[0] = tmp[0];
  T[1] = tmp[1];
  T[2] = tmp[2]; 
  T[3] = tmp[3]; 
  
  T = state->T6; 
  
  tmp[0] = _mm_aesenc_si128(T[5], T[0]) ^ M2; 
  tmp[1] = _mm_aesenc_si128(T[0], *(__m128i*)Z0); 
  tmp[2] = T[1]; 
  tmp[3] = T[2]; 
  tmp[4] = T[3]; 
  tmp[5] = T[4]; 

  T[0] = tmp[0];
  T[1] = tmp[1];
  T[2] = tmp[2]; 
  T[3] = tmp[3]; 
  T[4] = tmp[4]; 
  T[5] = tmp[5]; 

}

void init(TiaoxinState *state, const Byte K[], const Byte N[]) 
{
  ALIGN(16) Byte buff [16]; 
  for (int i = 0; i < 16; i++)
    buff[i] = K[i]; 

  state->T3[0] = _mm_loadu_si128((__m128i*)buff); 
  state->T3[1] = _mm_loadu_si128((__m128i*)buff); 
  state->T4[0] = _mm_loadu_si128((__m128i*)buff); 
  state->T4[1] = _mm_loadu_si128((__m128i*)buff); 
  state->T6[0] = _mm_loadu_si128((__m128i*)buff); 
  state->T6[1] = _mm_loadu_si128((__m128i*)buff); 
  
  for (int i = 0; i < 16; i++)
    buff[i] = N[i]; 

  state->T3[2] = _mm_loadu_si128((__m128i*)buff); 
  state->T4[2] = _mm_loadu_si128((__m128i*)buff); 
  state->T6[2] = _mm_loadu_si128((__m128i*)buff); 
  
  state->T4[3] = _mm_loadu_si128((__m128i*)Z0); 
  state->T6[3] = _mm_loadu_si128((__m128i*)Z1); 
  state->T6[4] = _mm_setzero_si128();
  state->T6[5] = _mm_setzero_si128();

  for (int i = 0; i < 16; i++)
    update(state, *(__m128i*)Z0, *(__m128i*)Z1, *(__m128i*)Z0); 
}

void encrypt(Byte *C, 
             Byte *T, 
             const Byte *M, 
             unsigned msg_len, 
             unsigned tag_len, 
             const Byte K[], 
             const Byte N[])
{
  TiaoxinState state; 
  ALIGN(16) Byte buff [16]; 
  __m128i M0, M1, C0, C1;  
  unsigned i; 

  assert(msg_len <= 32 /* Do last chunk only for now. */);
  //disp(&state); 
  
  init(&state, K, N); 
  
  *(__m128i*)buff = _mm_setzero_si128(); 
  for (i = 0; i < 16 && i < msg_len; i++)
    buff[i] = M[i]; 
  M0 = _mm_loadu_si128((__m128i*)buff);   

  *(__m128i*)buff = _mm_setzero_si128(); 
  for (; i < msg_len; i++)
    buff[i - 16] = M[i]; 
  M1 = _mm_loadu_si128((__m128i*)buff);   
 
  update(&state, M0, M1, M0 ^ M1); 
  C0 = state.T3[0] ^ state.T3[2] ^ state.T4[1] ^ (state.T6[3] & state.T4[3]);
  C1 = state.T6[0] ^ state.T4[2] ^ state.T3[1] ^ (state.T6[5] & state.T3[2]);
    
  _mm_storeu_si128((__m128i*)buff, C0);  
  for (i = 0; i < 16 && i < msg_len; i++)
    C[i] = buff[i];
  
  _mm_storeu_si128((__m128i*)buff, C1);  
  for (; i < msg_len; i++)
    C[i] = buff[i - 16];
  
  /* TODO authenticate */ 

}

int decrypt(Byte *M, 
            const Byte *C, 
            const Byte *T, 
            unsigned msg_len, 
            unsigned tag_len, 
            const Byte K[], 
            const Byte N[])
{
  TiaoxinState state; 
  ALIGN(16) Byte buff [16]; 
  __m128i M0, M1, C0, C1, zero = _mm_setzero_si128(); 
  unsigned i; 

  assert(msg_len <= 32 /* Do last chunk only for now. */);
  //disp(&state); 
  
  init(&state, K, N); 

  *(__m128i*)buff = _mm_setzero_si128(); 
  for (i = 0; i < 16 && i < msg_len; i++)
    buff[i] = C[i]; 
  C0 = _mm_loadu_si128((__m128i*)buff);   

  *(__m128i*)buff = _mm_setzero_si128(); 
  for (; i < msg_len; i++)
    buff[i - 16] = C[i]; 
  C1 = _mm_loadu_si128((__m128i*)buff);   
  
  update(&state, zero, zero, zero); 
  M0 = C0 ^ state.T3[0] ^ state.T3[2] ^ state.T4[1] ^ (state.T6[3] & state.T4[3]); 
  M1 = C1 ^ state.T6[0] ^ state.T4[2] ^ state.T3[1] ^ (state.T6[5] & state.T3[2]) ^ M0;
  state.T3[0] ^= M0; 
  state.T4[0] ^= M1; 
  state.T6[0] ^= M0 ^ M1;

  _mm_storeu_si128((__m128i*)buff, M0);  
  for (i = 0; i < 16 && i < msg_len; i++)
    M[i] = buff[i];
  
  _mm_storeu_si128((__m128i*)buff, M1);  
  for (; i < msg_len; i++)
    M[i] = buff[i - 16];

  /* TODO authenticate */ 
  return 0; 
}









int main(int argc, const char **argv) 
{

  Byte key [] =   {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};  
  Byte nonce [] = {0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0, 1}; 

  Byte message [] = "Hello, my name is Chris!!";
  Byte ciphertext [1024], plaintext [1024], tag [16]; 
  unsigned i, msg_len = strlen((const char *)message); 

  encrypt(ciphertext, tag, message, msg_len, 16, key, nonce); 
  decrypt(plaintext, ciphertext, tag, msg_len, 16, key, nonce); 
  
  printf("Message:    "); 
  for (i = 0; i < msg_len; i++)
    printf("%02x", message[i]); 
  printf(" (%d bytes)\n", msg_len); 

  printf("Plaintext:  "); 
  for (i = 0; i < msg_len; i++)
    printf("%02x", plaintext[i]); 
  printf("\n"); 
  
  printf("Ciphertext: "); 
  for (i = 0; i < msg_len; i++)
    printf("%02x", ciphertext[i]); 
  printf("\n"); 
  



  return 0; 
}
