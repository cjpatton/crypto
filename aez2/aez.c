/**
 * aez.c -- AEZv2, a Caesar submission proposed by Viet Tung Hoang, Ted 
 * Krovetz, and Phillip Rogaway. 
 *
 *   Written by Christopher Patton <chrispatton@gmail.com>.
 *
 * This program is dedicated to the public domain. 
 *
 * Last modified 17 Aug 2014. 
 */

#include "rijndael-alg-fst.h"
#include <stdint.h>
#include <assert.h>
#include <stdio.h>


/* ----- AEZ state --------------------------------------------------------- */

typedef unsigned char Byte; 

typedef Byte Block [16]; 

typedef struct {

  /* Key */ 
  Block Klong [11], Kshort [5]; 

  /* Tweak state */
  Block L, Linit, J [8]; 

} AezState; 


/* ---- Various primitives ------------------------------------------------- */ 

static void cp_block(Byte X [], const Byte Y [])
{
  for (int i = 0; i < 16; i++)
    X[i] = Y[i]; 
}

static void zero_block(Byte X [])
{
  for (int i = 0; i < 16; i++)
    X[i] = 0; 
}

static void xor_block(Byte X [], const Byte Y [], const Byte Z [])
{
  for (int i = 0; i < 16; i++)
    X[i] = Y[i] ^ Z[i]; 
}

/*
 * Multiply by two operation for key tweaking. 
 *  
 *   TODO The spec requires reversing the byte order before multiplying,
 *        then reversing the byte order of the resulting string. 
 */

static void dot2(Byte *b) {
  Byte tmp = b[0];
  for (int i = 0; i < 15; i++)
    b[i] = (Byte)((b[i] << 1) | (b[i+1] >> 7));
  b[15] = (Byte)((b[15] << 1) ^ ((tmp >> 7) * 135));
}

/*
 * Incremental tweak generation. Used to precompute multiples 
 * of the tweaks. 
 */
static void dot_inc(Block *Xs, int n)
{
  if (n == 0) 
    ;
  
  else if (n == 1)
    ; 

  else if (n == 2)
  {
    cp_block(Xs[2], Xs[1]);
    dot2(Xs[2]);
  }

  else if ((n % 2) == 1) // odd
  {
    cp_block(Xs[n], Xs[n-1]); 
    xor_block(Xs[n], Xs[n], Xs[1]);    
  }

  else // even
  {
    cp_block(Xs[n], Xs[n/2]);
    dot2(Xs[n]); 
  }
}


/* ----- AEZ initialization ------------------------------------------------ */ 

void init(AezState *state, const Byte K [], unsigned key_len)
{
  int i; 

  /* TODO K should be an arbitrary byte string expanded/extracted
   * into (J, L, K0, K1, K2, K3). For now these are fixed. */ 
  const Byte dumb [16] = "A dumb fixed key"; 

  cp_block(state->L, dumb);
  cp_block(state->Linit, dumb); 
  
  zero_block(state->J[0]); 
  cp_block(state->J[1], dumb); 
  for (i = 0; i < 8; i++)
    dot_inc(state->J, i); 

  /* TODO Modify AES4 call to accept tweak, since the key schedule's 
   * order depends on the tweak i. */ 
  cp_block(state->Kshort[0], dumb); 
  cp_block(state->Kshort[1], dumb); 
  cp_block(state->Kshort[2], dumb); 
  cp_block(state->Kshort[3], dumb); 
  zero_block(state->Kshort[4]); 

  rijndaelKeySetupEnc((uint32_t *)state->Klong, dumb, 128); 

}


/* ---- E^{i,j}_k(), the tweakable blockcipher ----------------------------- */

/*
 * A tweakable blockcipher with two parameters. `i` determines the key 
 * schedule and number of rounds for the AES call, and is any of {-1, 0, 1, 
 * 2, 3}. `j` actually corresponds to a two parameter tweak set, the first 
 * of which is a residue mod 8, the other doubling whenever 0 = j mod 8.
 *
 *   TODO Use appropriate key schedule for AES4 calls.
 */ 
void cipher(Byte C [], const Byte M [], int i, int j, AezState *state)
{
  if (i == -1) 
  {
    assert(0 <= j && j < 8);  
    xor_block(C, M, state->J[j]); 
    rijndaelEncrypt((uint32_t *)state->Klong, 10, C, C); 
  }

  else if (i == 0 || j == 0)
  {
    assert(0 <= j && j < 8);  
    xor_block(C, M, state->J[j]); 
    rijndaelEncrypt((uint32_t *)state->Kshort, 4, C, C); 
  }

  else 
  {
    unsigned res = j % 8; 
    xor_block(C, M, state->J[res]); 
    if (res == 0) 
      dot2(state->L); 
    xor_block(C, C, state->L); 
    rijndaelEncrypt((uint32_t *)state->Kshort, 4, C, C); 
  }

}


/* ---- AHash() ------------------------------------------------------------ */ 

/*
 * An XOR-almust-universal hash function based on AES4. Output length of `H` 
 * is 128 bits. `M` is an arbitrary length byte string of length `msg_len`. 
 */

void ahash(Byte H [], const Byte M [], unsigned msg_len, AezState *state)
{
  Byte buff [16]; 
  unsigned i, j = 0, k = msg_len / 16;  
  
  cp_block(state->L, state->Linit); /* Reset tweak. */ 
  zero_block(H); 

  /* Unfragmented blocks. */ 
  for (i = 0; i < k * 16; i += 16)
  {
    cipher(buff, &M[i], 3, j++, state);  
    xor_block(H, H, buff); 
  }

  /* Fragmented last block. */
  if (i < msg_len || i == 0) 
  {
    k = i; 
    for (; i < msg_len; i++)
      buff[i - k] = M[i]; 
    buff[i - k] = 0x80;
    cipher(buff, buff, 3, j++, state); 
    xor_block(H, H, buff); 
  }
  
  cp_block(state->L, state->Linit); /* Reset tweak. */ 
}


/* ---- AMac() ------------------------------------------------------------- */

/*
 * A secure message authentication code based on AHash(). Output length of `H`
 * is 128 bits. `M` is an arbitrary length byte string of length `msg_len`. 
 */

void amac(Byte T [], const Byte M [], unsigned msg_len, AezState *state)
{
  ahash(T, M, msg_len, state); 
  cipher(T, T, -1, 5, state); 
}


/* ---- Encipher() ----------------------------------------------------------- */

/*
 * EncipherEME4, the meat of AEZv2. 
 */ 
void encipher_eme4(Byte C [], 
                   const Byte M [], 
                   const Byte T [], 
                   unsigned msg_len,
                   unsigned tag_len, 
                   unsigned inv,
                   AezState *state)
{
  Block delta, X, R0 /* R */, R1 /* R' */, S; 
  unsigned i, j = 0, k = msg_len / 32;  
  
  ahash(delta, T, tag_len, state);
  zero_block(X); 

  /* X; X0, X'0, ... Xm, X'm */ 
  for (i = 0; i < k * 32; i += 32)
  {
    /* M = &M[i], M' = &M[i+16] */ 
    cipher(&C[i+16], &M[i+16], 1, j, state); 
    xor_block(&C[i+16], &C[i+16], &M[i]); 

    cipher(&C[i], &C[i+16], 0, 0, state); 
    xor_block(&C[i], &C[i], &M[i+16]); 

    xor_block(X, X, &C[i]); 
    xor_block(X, X, &C[i+16]); 
    ++j; 
  }

  /* R, R'; S */ 
  xor_block(R0, X, &M[16]);
  if (!inv)
    cipher(R0, R0, 0, 1, state); 
  else
    cipher(R0, R0, 0, 2, state); 
  xor_block(R0, R0, M); 
  xor_block(R0, R0, delta); // R

  if (!inv)
    cipher(R1, R0, -1, 1, state); 
  else 
    cipher(R1, R0, -1, 2, state); 

  xor_block(R1, R1, &M[16]); 
  xor_block(R1, R1, X); // R' 

  xor_block(S, R0, R1); // S

  
    // TODO 
  
  

}

void encipher_ff0(Byte C [], 
                  const Byte M [], 
                  const Byte T [], 
                  unsigned msg_len,
                  unsigned tag_len, 
                  unsigned inv,
                  AezState *state)
{
  printf("not implemented\n");  
}

void encipher(Byte C [], 
              const Byte M [], 
              const Byte T [], 
              unsigned msg_len,
              unsigned tag_len, 
              AezState *state)
{
  if (msg_len < 32) 
    encipher_ff0(C, M, T, msg_len, tag_len, 0, state); 
  else
    encipher_eme4(C, M, T, msg_len, tag_len, 0, state); 
}

void decipher(Byte C [], 
              const Byte M [], 
              const Byte T [], 
              unsigned msg_len,
              unsigned tag_len, 
              AezState *state)
{
  if (msg_len < 32) 
    encipher_ff0(C, M, T, msg_len, tag_len, 1, state); 
  else
    encipher_eme4(C, M, T, msg_len, tag_len, 1, state); 
}



/* ----- Testing, testing ... ---------------------------------------------- */

#include <string.h>
#include <time.h>

static void display_block(const Block X) 
{
  for (int i = 0; i < 4; i ++)
    printf("0x%08x ", *(uint32_t *)&X[i * 4]); 
}

static void display_state(AezState *state)
{
  unsigned i; 
  printf("+---------------------------------------------------------+\n"); 
  for (i = 0; i < 11; i++)
  {
    printf("| Klong[%-2d] = ", i); 
    display_block(state->Klong[i]); 
    printf("|\n"); 
  }

  printf("+---------------------------------------------------------+\n"); 
  for (i = 0; i < 5; i++)
  {
    printf("| Kshort[%d] = ", i); 
    display_block(state->Kshort[i]); 
    printf("|\n"); 
  }

  printf("+---------------------------------------------------------+\n"); 
  for (i = 0; i < 8; i++)
  {
    printf("| J[%-2d] =     ", i); 
    display_block(state->J[i]); 
    printf("|\n"); 
  }

  printf("+---------------------------------------------------------+\n"); 
  printf("| L     =     "); 
  display_block(state->L); 
  printf("|\n"); 
  
  printf("| Linit =     "); 
  display_block(state->Linit); 
  printf("|\n"); 
  printf("+---------------------------------------------------------+\n"); 
}

int main()
{
  AezState state; 
  init(&state, NULL, 0); 
  //display_state(&state); 
  
  Byte tag [1024] = "This is a really, really great tag.",
       message[1024] = "0123456789abcdef0123456789abcdef", 
       ciphertext[1024], plaintext [1024]; 
  unsigned msg_len = strlen((const char *)message),
           tag_len = strlen((const char *)tag), i; 

  /* Encipher(). */
  memset(ciphertext, 0, 1024); memset(plaintext, 0, 1024); 
  encipher(ciphertext, message, tag, msg_len, tag_len, &state); 
  decipher(plaintext, ciphertext, tag, msg_len, tag_len, &state); 

  printf("Message: "); 
  for (i = 0; i < msg_len; i++)
    printf("%c", plaintext[i]); 
  printf(" (%d bytes)\n", msg_len); 


  /* AHash(). */
  //ahash(tag, message, msg_len, &state); 
  //printf("Hash: "); display_block(tag); printf("\n");  
  
  /* AMac(). */
  //amac(tag, message, msg_len, &state); 
  //printf("Mac:  "); display_block(tag); printf("\n");  


  return 0; 
}

