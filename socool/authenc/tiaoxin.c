/** 
 * tiaoxin.c -- An independent implementation of Tiaoxin-346, designed by 
 * Ivica Nikolic and submitted in the CAESAR authenticated encryption scheme 
 * competition. This program uses the AES-NI instruction set for modern x86
 * processors. Compile with gcc flags "-O3 -std=c99 -maes -mssse3".  
 *
 *   Written by Christopher Patton.
 *
 * This porgram is dedicated to the public domain.
 */

/*
 * Last modified on 9 Aug 2014.  
 *
 * NOTE Is it OK to pass an unaligned byte buffer to AES load instruction? 
 *      Yes! _mm_load_si128() is the aligned version; I'm using 
 *      _mm_loadu_si128().
 *
 * TODO Trim down the update function if possible. 
 *
 * TODO Processing of additional data. 
 */

#include <stdint.h>
#include <wmmintrin.h>
#include <tmmintrin.h>
#include <string.h>
#include <stdio.h>

#define ALIGN(n) __attribute__ ((aligned(n)))

typedef unsigned char Byte; 


/* ---- Tiaoxin-346 constants. --------------------------------------------- */ 

ALIGN(16) const Byte Z0 [] = {0x42, 0x8a, 0x2f, 0x98,
                              0xd7, 0x28, 0xae, 0x22, 
                              0x71, 0x37, 0x44, 0x91,
                              0x23, 0xef, 0x65, 0xcd}; 

ALIGN(16) const Byte Z1 [] = {0xb5, 0xc0, 0xfb, 0xcf,
                              0xec, 0x4d, 0x3b, 0x2f,
                              0xe9, 0xb5, 0xdb, 0xa5,
                              0x81, 0x89, 0xdb, 0xbc}; 


/* ---- Tiaoxin-346 state. ------------------------------------------------- */ 

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
} // disp()


/* ----- Tiaoxin-346 update funciton. -------------------------------------- */

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
} // update() 


/* ----- Tiaxin-346 initialization. ---------------------------------------- */ 

/* 
 * Initialize the state with key (K) and nonce (N). 
 *
 *   TODO Process additional data. 
 */ 

void init(TiaoxinState *state, const __m128i *K, const __m128i *N) 
{
  state->T3[0] = _mm_loadu_si128(K); 
  state->T3[1] = _mm_loadu_si128(K); 
  state->T4[0] = _mm_loadu_si128(K); 
  state->T4[1] = _mm_loadu_si128(K); 
  state->T6[0] = _mm_loadu_si128(K); 
  state->T6[1] = _mm_loadu_si128(K); 
  
  state->T3[2] = _mm_loadu_si128(N); 
  state->T4[2] = _mm_loadu_si128(N); 
  state->T6[2] = _mm_loadu_si128(N); 
  
  state->T4[3] = _mm_loadu_si128((__m128i*)Z0); 
  state->T6[3] = _mm_loadu_si128((__m128i*)Z1); 
  state->T6[4] = _mm_setzero_si128();
  state->T6[5] = _mm_setzero_si128();

  for (int i = 0; i < 16; i++)
    update(state, *(__m128i*)Z0, *(__m128i*)Z1, *(__m128i*)Z0); 
} // init() 


/* ----- Tiaoxin-346 authentication. --------------------------------------- */ 

/* 
 * Update a post-encryption or -decryption state with the lengths of the 
 * message and additional data encoded as blocks. Mix the state another 20 
 * rounds and XOR the block states to produce the tag. 
 *   
 *  TODO Length of additional data.  
 */

void auth(Byte *T, unsigned tag_len, unsigned msg_len, TiaoxinState *state)
{
  ALIGN(16) Byte buff [16]; 
  __m128i AD, M;
  unsigned i;
  AD = _mm_setzero_si128(); ((unsigned *)&AD)[0] = 0/* ad_len */; 
  M = _mm_setzero_si128();  ((unsigned *)&M)[0] = msg_len;
  
  update(state, AD, M, AD ^ M); 
  for (i = 0; i < 20; i++)
    update(state, *(__m128i*)Z1, *(__m128i*)Z0, *(__m128i*)Z1); 

  M = state->T3[0] ^ state->T3[1] ^ state->T3[2] ^ 
      state->T4[0] ^ state->T4[1] ^ state->T4[2] ^ state->T4[3] ^
      state->T6[0] ^ state->T6[1] ^ state->T6[2] ^ state->T6[3] ^ 
        state->T6[4] ^ state->T6[5]; 

  _mm_storeu_si128((__m128i*)buff, M);  
  for (i = 0; i < tag_len; i++)
    T[i] = buff[i]; 
} // auth() 


/* ----- Tiaoxin-346 authenticated encryption. ----------------------------- */

void encrypt(Byte *C, 
             Byte *T, 
             const Byte *M, 
             unsigned msg_len, 
             unsigned tag_len, 
             const __m128i *K, 
             const __m128i *N)
{
  TiaoxinState state; 
  ALIGN(16) Byte buff [16]; 
  __m128i M0, M1, C0, C1;  
  unsigned i, j, num_blocks = msg_len / 32; 

  init(&state, K, N); 

  /* Unfragmented blocks */ 
  for (j = 0; j < num_blocks * 32; j += 32)
  {
    M0 = _mm_loadu_si128((__m128i*)&M[j]);   
    M1 = _mm_loadu_si128((__m128i*)&M[j + 16]);   
  
    update(&state, M0, M1, M0 ^ M1); 
    C0 = state.T3[0] ^ state.T3[2] ^ state.T4[1] ^ (state.T6[3] & state.T4[3]);
    C1 = state.T6[0] ^ state.T4[2] ^ state.T3[1] ^ (state.T6[5] & state.T3[2]);
    
    _mm_storeu_si128((__m128i*)&C[j], C0);  
    _mm_storeu_si128((__m128i*)&C[j + 16], C1);  
  }

  /* Fragmented last block */  
  *(__m128i*)buff = _mm_setzero_si128(); 
  for (i = j; i < 16 + j && i < msg_len; i++)
    buff[i - j] = M[i]; 
  M0 = _mm_loadu_si128((__m128i*)buff);   

  *(__m128i*)buff = _mm_setzero_si128(); 
  for (; i < msg_len; i++)
    buff[i - j - 16] = M[i]; 
  M1 = _mm_loadu_si128((__m128i*)buff);   
 
  update(&state, M0, M1, M0 ^ M1); 
  C0 = state.T3[0] ^ state.T3[2] ^ state.T4[1] ^ (state.T6[3] & state.T4[3]);
  C1 = state.T6[0] ^ state.T4[2] ^ state.T3[1] ^ (state.T6[5] & state.T3[2]);
    
  _mm_storeu_si128((__m128i*)buff, C0);  
  for (i = j; i < 16 + j && i < msg_len; i++)
    C[i] = buff[i - j];
  
  _mm_storeu_si128((__m128i*)buff, C1);  
  for (; i < msg_len; i++)
    C[i] = buff[i - j - 16];
  
  /* Generate tag */ 
  auth(T, tag_len, msg_len, &state); 
} // encrypt() 


/* ----- Tiaoxin-346 authenticated decryption. ----------------------------- */ 

/* 
 * Decrypt, verify tag. Return 1 if the tag is valid, 0 to rject. Prevent 
 * releasing the plaintext by destroying it. 
 */  

int decrypt(Byte *M, 
            const Byte *C, 
            const Byte *T, 
            unsigned msg_len, 
            unsigned tag_len, 
            const __m128i *K, 
            const __m128i *N)
{
  TiaoxinState state; 
  ALIGN(16) Byte buff [16]; 
  __m128i M0, M1, C0, C1, zero = _mm_setzero_si128(); 
  unsigned i, j, num_blocks = msg_len / 32; 

  init(&state, K, N); 

  /* Unfragmented blocks */ 
  for (j = 0; j < num_blocks * 32; j += 32)
  {
    C0 = _mm_loadu_si128((__m128i*)&C[j]);   
    C1 = _mm_loadu_si128((__m128i*)&C[j + 16]);   
  
    update(&state, zero, zero, zero); 
    M0 = C0 ^ state.T3[0] ^ state.T3[2] ^ state.T4[1] ^ (state.T6[3] & state.T4[3]); 
    M1 = C1 ^ state.T6[0] ^ state.T4[2] ^ state.T3[1] ^ (state.T6[5] & state.T3[2]) ^ M0;
    state.T3[0] ^= M0; 
    state.T4[0] ^= M1; 
    state.T6[0] ^= M0 ^ M1;
    
    _mm_storeu_si128((__m128i*)&M[j], M0);  
    _mm_storeu_si128((__m128i*)&M[j + 16], M1);  
  }

  /* Fragmented last block */  
  *(__m128i*)buff = _mm_setzero_si128(); 
  for (i = j; i < 16 + j && i < msg_len; i++)
    buff[i - j] = C[i]; 
  C0 = _mm_loadu_si128((__m128i*)buff);   

  *(__m128i*)buff = _mm_setzero_si128(); 
  for (; i < msg_len; i++)
    buff[i - j - 16] = C[i]; 
  C1 = _mm_loadu_si128((__m128i*)buff);   
  
  update(&state, zero, zero, zero); 
  M0 = C0 ^ state.T3[0] ^ state.T3[2] ^ state.T4[1] ^ (state.T6[3] & state.T4[3]); 
  M1 = C1 ^ state.T6[0] ^ state.T4[2] ^ state.T3[1] ^ (state.T6[5] & state.T3[2]) ^ M0;

  _mm_storeu_si128((__m128i*)buff, M0); 
  for (i = j; i < 16 + j && i < msg_len; i++)
  {
    ((Byte *)&(state.T3[0]))[i - j] ^= buff[i - j];  
    ((Byte *)&(state.T6[0]))[i - j] ^= buff[i - j];  
    M[i] = buff[i - j];
  }

  _mm_storeu_si128((__m128i*)buff, M1);  
  for (; i < msg_len; i++) 
  {
    ((Byte *)&(state.T4[0]))[i - j - 16] ^= buff[i - j - 16];  
    ((Byte *)&(state.T6[0]))[i - j - 16] ^= buff[i - j - 16];  
    M[i] = buff[i - j - 16];
  }

  /* Verify tag. If reject, destroy plaintext. */ 
  auth(buff, tag_len, msg_len, &state); 
  if (strncmp((const char *)buff, (const char *)T, tag_len) != 0)
  {
    memset(M, 0, msg_len * sizeof(Byte)); 
    return 0; 
  }
  else return 1; 
} // decrypt() 



/* ----- Testing, testing ... ---------------------------------------------- */ 

#include <time.h>
#include <stdlib.h> 

#define HZ (2.9e9) 
#define TRIALS 1000000

void benchmark() {

  static const int msg_len [] = {64,     128,  256,   512, 
                                 1024,   4096, 10000, 100000,
                                 1000000}; 
  static const int num_msg_lens = 8; 
  
  Byte key [] =   {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};  
  __m128i K = _mm_loadu_si128((__m128i *)key); 
  __m128i N = _mm_setzero_si128(); 

  Byte tag [16]; 
  Byte *message = malloc(msg_len[num_msg_lens-1] * sizeof(Byte)); 
  Byte *ciphertext = malloc(msg_len[num_msg_lens-1] * sizeof(Byte)); 
  Byte *plaintext = malloc(msg_len[num_msg_lens-1] * sizeof(Byte)); 

  unsigned i, j; 
  clock_t t; 
  double total_cycles; 
  double total_bytes; 

  for (i = 0; i < num_msg_lens; i++)
  {
    t = clock(); 
    for (j = 0; j < TRIALS; j++)
    {
      encrypt(ciphertext, tag, message, msg_len[i], 16, &K, &N); 
      N ++; 
    }
    t = clock() - t; 
    total_cycles = t * HZ / CLOCKS_PER_SEC; 
    total_bytes = (double)TRIALS * msg_len[i]; 
    printf("%8d bytes, %.2f cycles per byte\n", msg_len[i], 
                               total_cycles/total_bytes); 
  }
  
  //ciphertext[343] = 'o';
  N --; i --; 
  if (decrypt(plaintext, ciphertext, tag, msg_len[i], 16, &K, &N))
    printf("Success! ");
  else 
    printf("Tag mismatch. ");
  for (i = 0; i < 16; i++)
    printf("%02x", tag[i]); 
  printf("\n"); 

  free(message); 
  free(ciphertext); 
  free(plaintext); 
}

int main(int argc, const char **argv) 
{

  benchmark();
  
  return 0; 
}
