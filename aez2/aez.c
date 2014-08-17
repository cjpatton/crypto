/**
 * aez.c -- AEZ v 2, a Caesar submission submitted by Viet Tung Haong, Ted 
 * Krovetz, and Phillip Rogaway. 
 */

#include "rijndael-alg-fst.h"
#include <stdint.h>
#include <assert.h>

typedef unsigned char Byte; 
typedef Byte Block [16]; 

void cp_block(Byte X [], const Byte Y [])
{
  for (int i = 0; i < 16; i++)
    X[i] = Y[i]; 
}

void zero_block(Byte X [])
{
  for (int i = 0; i < 16; i++)
    X[i] = 0; 
}

void xor_block(Byte X [], const Byte Y [], const Byte Z [])
{
  for (int i = 0; i < 16; i++)
    X[i] = Y[i] ^ Z[i]; 
}


/* ----- AEZ state --------------------------------------------------------- */

typedef struct {

  /* Key */ 
  Block Klong [11], Kshort [5]; 

  /* Tweak state */
  Block L, Linit, J [8]; 

} AezState; 


/* ----- AEZ initialization and key tweaking ------------------------------- */ 

static void dot2(Byte *b) {
    Byte tmp = b[0];
    unsigned i;
    for (i=0; i<15; i++)
        b[i] = (Byte)((b[i] << 1) | (b[i+1] >> 7));
    b[15] = (Byte)((b[15] << 1) ^ ((tmp >> 7) * 135));
}

/*
 * Precompute array of values for incrementing tweak (i ++) 
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



/* ---- AHash() ------------------------------------------------------------ */ 

void ahash(Byte H [], const Byte M [], unsigned msg_len, AezState *state)
{

}




/* ----- Testing, testing ... ---------------------------------------------- */

#include <string.h>
#include <stdio.h>
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
  display_state(&state); 
  return 0; 
}

