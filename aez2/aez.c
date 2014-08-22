/**
 * aez.c -- AEZv2, a Caesar submission proposed by Viet Tung Hoang, Ted 
 * Krovetz, and Phillip Rogaway. 
 *
 *   Written by Chris Patton <chrispatton@gmail.com>.
 *
 * This program is dedicated to the public domain. 
 *
 * TODO 
 *  - Byte order of custom AES keys. 
 *  - Point swap in FF0. 
 *  - Encrypt(), Decrypt(), Format()
 *
 * Last modified 17 Aug 2014. 
 */

#include "rijndael-alg-fst.h"
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

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
 *   NOTE The spec requires reversing the byte order before multiplying,
 *        then reversing the byte order of the resulting string. This is 
 *        done for efficient implemenation on little endian systems. We 
 *        relax this here. 
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

  else if (n & 1) // odd
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


/* ----- AEZ initialization, Extract(), Expand()  --------------------------- */ 

void extract(Block J, Block L, const Byte K [], unsigned key_len)
{
  unsigned i, j; 
  Block a[5], b[5], C[8], buff; 
 
  for (i = 0; i < 5; i++) 
  {
    for (j = 0; j < 16; j++)
      a[i][j] = (Byte)j;
    // FIXME byte order of custom AES4 key.
  }

  zero_block(buff); 
  for (i = 0; i < 7; i++)
  {
    buff[0] ++; 
    rijndaelEncrypt((uint32_t *)a, 4, buff, C[i]); 
  }

  zero_block(a[0]); 
  cp_block(a[1], C[0]); 
  cp_block(a[2], C[1]); 
  cp_block(a[3], C[2]); 
  zero_block(a[4]);

  zero_block(b[0]); 
  cp_block(b[1], C[3]); 
  cp_block(b[2], C[4]); 
  cp_block(b[3], C[5]); 
  zero_block(b[4]);
  // FIXME byte order of custom AES4 keys `a` and `b`. 
  
  cp_block(C[2], C[6]); 
  j = key_len - (key_len % 16); 
  zero_block(J); zero_block(L);
  for (i = 0; i < j; i += 16)
  {
    /* C = C[6], C[2] is the doubling version. 
     * C[0], C[1] are used as buffers. */
    xor_block(buff, &K[i], C[2]); 
    rijndaelEncrypt((uint32_t *)a, 4, buff, C[0]); 
    rijndaelEncrypt((uint32_t *)b, 4, buff, C[1]); 
    xor_block(J, J, C[0]); 
    xor_block(L, L, C[1]); 
    dot2(C[2]); 
  }

  if (i < key_len) 
  {
    zero_block(buff);
    for (j = i; i < key_len; i++) 
      buff[i - j] = K[i]; 
    buff[i - j] = 0x80; 
    xor_block(buff, C[2], C[6]); /* dot(3, C) */  
    rijndaelEncrypt((uint32_t *)a, 4, buff, C[0]); 
    rijndaelEncrypt((uint32_t *)b, 4, buff, C[1]); 
    xor_block(J, J, C[0]); 
    xor_block(L, L, C[1]); 
  }
} // extract()

/* 
 * Expand extracted key (J, L) into AES4 key scheudle. 
 */
void expand(Block Kshort[], const Block J, const Block L)
{
  unsigned i;
  Block k [5], buff;

  cp_block(k[0], J); 
  cp_block(k[1], L); 
  cp_block(k[2], k[0]); dot2(k[2]); 
  cp_block(k[3], L);
  cp_block(k[4], k[2]); dot2(k[4]);
  // FIXME Byte order of custom AES keys.

  zero_block(Kshort[4]); 
  zero_block(k[5]); 
  zero_block(buff);
  for (i = 0; i < 4; i++) 
  {
    buff[0] ++; 
    rijndaelEncrypt((uint32_t *)k, 4, buff, Kshort[i]); 
  }
} // expand() 

/*
 * Extract key material, set up key schedules and tweak context.  
 */
void init(AezState *state, const Byte K [], unsigned key_len)
{
  unsigned i; 

  /* Get J, L, and Kshort from user key. */ 
  // FIXME byte order of custom AES key. 
  extract(state->J[1], state->L, K, key_len); 
  expand(state->Kshort, state->J[1], state->L); 

  /* We need to be able to reset doubling L tweak. */ 
  cp_block(state->Linit, state->L);

  /* Precompute tweaks on J. */ 
  zero_block(state->J[0]); 
  for (i = 0; i < 8; i++)
    dot_inc(state->J, i); 

  /* Set up Klong. NOTE that we could expand the key in the full
   * key schedule and remove Kshort to reduce the state size. */ 
  // FIXME byte order of custom AES key.
  cp_block(state->Klong[0], state->L); // L
  cp_block(state->Klong[1], state->J[1]); // J 
  cp_block(state->Klong[2], state->Klong[1]); dot2(state->Klong[2]); // 2J
  cp_block(state->Klong[3], state->Klong[2]); dot2(state->Klong[3]); // 4J
  cp_block(state->Klong[4], state->Kshort[0]); // K0
  cp_block(state->Klong[5], state->Kshort[1]); // K1
  cp_block(state->Klong[6], state->Kshort[2]); // K2
  cp_block(state->Klong[7], state->Kshort[3]); // K3
  cp_block(state->Klong[8], state->Kshort[0]); // K0
  cp_block(state->Klong[9], state->Kshort[1]); // K1
  cp_block(state->Klong[10], state->Kshort[2]); // K2
} // init() 


/* ---- E^{i,j}_k(), the tweakable blockcipher ----------------------------- */

/*
 * A tweakable blockcipher with two parameters. `i` determines the key 
 * schedule and number of rounds for the AES4 call, and is any of {-1, 0, 1, 
 * 2, 3}. -1 signals standard 10-round AES. `j` actually corresponds to a point in
 * a two parameter tweak set, the first of which is a residue mod 8, the other 
 * doubling whenever 0 = j mod 8. Doubling is handled by variant() and reset().
 *
 *   TODO Double check AES4 calls.
 */ 
void cipher(Byte C [], const Byte M [], int i, int j, AezState *state)
{
  if (i == -1) /* 0 <= j < 8 */ 
  {
    xor_block(C, M, state->J[j]); 
    rijndaelEncrypt((uint32_t *)state->Klong, 10, C, C); 
  }

  else if (i == 0 || j == 0) /* 0 <= j < 8 */ 
  {
    xor_block(C, M, state->J[j]); 
    rijndaelEncryptRound((uint32_t *)state->Kshort, 4, C, i+1); 
  }

  else 
  {
    xor_block(C, M, state->J[j % 8]); 
    xor_block(C, C, state->L); 
    rijndaelEncryptRound((uint32_t *)state->Kshort, 4, C, i+1); 
  }

}

/*
 * Update doubling tweak `T` if necessary. `i` doesn't actually
 * have an affect on the tweak. 
 */
static void variant(AezState *state, int i, int j) 
{
  if (j % 8 == 0)
    dot2(state->L); 
}

/*
 * Reset tweak. 
 */
static void reset(AezState *state)
{
  cp_block(state->L, state->Linit);
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
  
  reset(state); 
  zero_block(H); 

  /* Unfragmented blocks. */ 
  for (i = 0; i < k * 16; i += 16)
  {
    variant(state, i, ++j); 
    cipher(buff, &M[i], 3, j, state);  
    xor_block(H, H, buff); 
  }

  /* Fragmented last block. */
  if (i < msg_len || i == 0) 
  {
    k = i; 
    for (; i < msg_len; i++)
      buff[i - k] = M[i]; 
    buff[i - k] = 0x80;
    cipher(buff, buff, 0, 1, state); 
    xor_block(H, H, buff); 
  }
  
  reset(state); 
} // AHash()


/* ---- AMac() ------------------------------------------------------------- */

/*
 * A secure message authentication code based on AHash(). Output length of `H`
 * is 128 bits. `M` is an arbitrary length byte string of length `msg_len`. 
 */

void amac(Byte T [], const Byte M [], unsigned msg_len, AezState *state)
{
  ahash(T, M, msg_len, state); 
  cipher(T, T, -1, 5, state); 
} // AMac() 


/* ---- Encipher(), Decipher() ---------------------------------------------- */

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
  Block buff, delta, X, Y, Z, R0 /* R */, R1 /* R' */, S, Y0, Y1; 
  unsigned i, j, k = msg_len / 32;  
  
  ahash(delta, T, tag_len, state);
  zero_block(X); 

  /* X; X1, X'1, ... Xm, X'm */ 
  reset(state); 
  for (j = 0, i = 32; i < k * 32; i += 32)
  {
    /* M = &M[i], M' = &M[i+16] */ 
    variant(state, i, ++j); 
    cipher(&C[i+16], &M[i+16], 1, j, state); 
    xor_block(&C[i+16], &C[i+16], &M[i]); 

    cipher(&C[i], &C[i+16], 0, 0, state); 
    xor_block(&C[i], &C[i], &M[i+16]); 

    xor_block(X, X, &C[i]); 
  }

  if (msg_len - i > 0 && msg_len - i < 16) /* M* */ 
  {
    zero_block(buff); 
    for (j = i; i < msg_len; i++)
      buff[i - j] = M[i]; 
    buff[i - j] = 0x80; 
    cipher(buff, buff, 0, 3, state); 
    
    for (j = i; i < msg_len; i++)
      X[i - j] ^= buff[i - j];
  }
  
  else if (msg_len - i > 0) /* M*, M** */
  {
    cipher(buff, &M[i], 0, 3, state); 
    xor_block(X, X, buff); 
  
    i += 16; 
    zero_block(buff); 
    for (j = i; i < msg_len; i++)
      buff[i - j] = M[i]; 
    buff[i - j] = 0x80; 
    cipher(buff, buff, 0, 4, state); 
    
    for (j = i; i < msg_len; i++)
      X[i - j] ^= buff[i - j];
  }

  /* R, R'; S */ 
  xor_block(R0, X, &M[16]);
  if (!inv) cipher(R0, R0, 0, 1, state); 
  else      cipher(R0, R0, 0, 2, state); 
  xor_block(R0, R0, M); 
  xor_block(R0, R0, delta); // R

  if (!inv) cipher(R1, R0, -1, 1, state); 
  else      cipher(R1, R0, -1, 2, state); 
  xor_block(R1, R1, &M[16]); 
  xor_block(R1, R1, X); // R' 

  xor_block(S, R0, R1); // S
  zero_block(Y);

  /* Y; C1, C'1, ... Cm, C'm */ 
  reset(state); 
  for (j = 0, i = 32; i < k * 32; i += 32)
  {
    variant(state, i, ++j); 

    /* X = &C[i], X' = &C[i+16]; Y0 = Yi, Y1 = Y'i*/ 
    cipher(Z, S, 2, j, state); 
    xor_block(Y0, &C[i+16], Z);
    xor_block(Y1, &C[i], Z);
    
    cipher(&C[i+16], Y1, 0, 0, state); 
    xor_block(&C[i+16], &C[i+16], Y0); 

    cipher(&C[i], &C[i+16], 1, j, state); 
    xor_block(&C[i], &C[i], Y1); 

    xor_block(Y, Y, Y0); 
  }
  
  if (msg_len - i > 0 && msg_len - i < 16) /* C* */ 
  {
    cipher(buff, S, -1, 3, state); 
    for (j = i; i < msg_len; i++) 
      C[i] = M[i] ^ buff[i - j];
    
    zero_block(buff); 
    for (j = i; i < msg_len; i++) 
      buff[i - j] = C[i]; 
    buff[i - j] = 0x80; 
    cipher(buff, buff, 0, 3, state); 

    for (j = i; i < msg_len; i++)
      Y[i- j] ^= buff[i - j];
  }

  else if (msg_len - i > 0) /* C*, C** */ 
  {
    cipher(buff, S, -1, 3, state); 
    xor_block(&C[i], &M[i], buff); 
    cipher(buff, &C[i], 0, 3, state); 
    xor_block(Y, Y, buff); 

    i += 16; 
    cipher(buff, S, -1, 4, state); 
    for (j = i; i < msg_len; i++) 
      C[i] = M[i] ^ buff[i - j];
    
    zero_block(buff); 
    for (j = i; i < msg_len; i++) 
      buff[i - j] = C[i]; 
    buff[i - j] = 0x80; 
    cipher(buff, buff, 0, 4, state); 

    for (j = i; i < msg_len; i++)
      Y[i- j] ^= buff[i - j];
  }
  
  if (!inv) cipher(buff, R1, -1, 2, state); 
  else      cipher(buff, R1, -1, 1, state); 
  xor_block(&C[16], R0, buff); 

  if (!inv) cipher(C, &C[16], 0, 2, state);
  else      cipher(C, &C[16], 0, 1, state);
  xor_block(C, C, R1); 
  xor_block(C, C, delta); 
  xor_block(&C[16], &C[16], Y); 

  reset(state); 
} // EncipherEME4()


/*
 * EncipherFF0() -- scheme for small messages (< 32). There are no 
 * provable security results for this scheme ... the number of 
 * Feistel round depends on the message length and is chosen 
 * heurestically. The code is derived from Ted Krovetz' reference
 * implementation of AEZv1. 
 *
 *   TODO Point swap. 
 */
void encipher_ff0(Byte C [], 
                  const Byte M [], 
                  const Byte T [], 
                  unsigned msg_len,
                  unsigned tag_len, 
                  unsigned inv,
                  AezState *state)
{
  int i, j, k, l, n = msg_len / 2;
  Block delta, front, back;
  Byte mask=0x00, pad=0x80, ctr,
       buff [32], *A, *B;  
  
  if (msg_len == 1)      k = 24; 
  else if (msg_len == 2) k = 16;
  else if (msg_len < 16) k = 10; 
  else                   k = 8;

  if (msg_len >= 16) j = 5; 
  else               j = 6; 

  ahash(delta, T, tag_len, state); 
  
  l = (msg_len + 1) / 2; 
  
  memcpy(front, M, l); 
  memcpy(back, &M[n], l); 

  if (msg_len & 1)
  {
    for (i = 0; i < n; i++)
      back[i] = (Byte)((back[i] << 4) | (back[i+1] >> 4));
    back[n] = (Byte)(back[n] << 4);
    pad = 0x08; mask = 0xf0;
  }

  if (inv) { B = front; A = back; ctr = k - 1; } 
  else     { A = front; B = back; ctr = 0; }

  for (i = 0; i < k; i += 2)
  {
    zero_block(buff);
    memcpy(buff, B, l);
    buff[n] = (buff[n] & mask) | pad; 
    xor_block(buff, buff, delta);
    buff[0] ^= ctr; 
    cipher(buff, buff, 0, j, state); 
    xor_block(A, A, buff); 
    if (!inv) ++ctr;
    else      --ctr; 

    zero_block(buff); 
    memcpy(buff, A, l); 
    buff[n] = (buff[n] & mask) | pad; 
    xor_block(buff, buff, delta);
    buff[0] ^= ctr; 
    cipher(buff, buff, 0, j, state); 
    xor_block(B, B, buff); 
    if (!inv) ++ctr;
    else      --ctr; 
  }
    
  memcpy(buff, front, n);
  memcpy(&buff[n], back, l);
  if (msg_len & 1) 
  {
    for (i = msg_len - 1; i > n; i--)
       buff[i] = (Byte)((buff[i] >> 4) | (buff[i-1] << 4));
     buff[n] = (Byte)((back[0] >> 4) | (front[n] & mask));
  }
  memcpy(C, buff, msg_len);
} // EncipherFF0() 


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

void decipher(Byte M [], 
              const Byte C [], 
              const Byte T [], 
              unsigned msg_len,
              unsigned tag_len, 
              AezState *state)
{
  if (msg_len < 32) 
    encipher_ff0(M, C, T, msg_len, tag_len, 1, state); 
  else
    encipher_eme4(M, C, T, msg_len, tag_len, 1, state); 
}


/* ----- Testing, testing ... ---------------------------------------------- */

#include <string.h>
#include <time.h>

//static void display_block(const Block X) 
//{
//  for (int i = 0; i < 4; i ++)
//    printf("0x%08x ", *(uint32_t *)&X[i * 4]); 
//}

//static void display_state(AezState *state)
//{
//  unsigned i; 
//  printf("+---------------------------------------------------------+\n"); 
//  for (i = 0; i < 11; i++)
//  {
//    printf("| Klong[%-2d] = ", i); 
//    display_block(state->Klong[i]); 
//    printf("|\n"); 
//  }
//
//  printf("+---------------------------------------------------------+\n"); 
//  for (i = 0; i < 5; i++)
//  {
//    printf("| Kshort[%d] = ", i); 
//    display_block(state->Kshort[i]); 
//    printf("|\n"); 
//  }
//
//  printf("+---------------------------------------------------------+\n"); 
//  for (i = 0; i < 8; i++)
//  {
//    printf("| J[%-2d] =     ", i); 
//    display_block(state->J[i]); 
//    printf("|\n"); 
//  }
//
//  printf("+---------------------------------------------------------+\n"); 
//  printf("| L     =     "); 
//  display_block(state->L); 
//  printf("|\n"); 
//  
//  printf("| Linit =     "); 
//  display_block(state->Linit); 
//  printf("|\n"); 
//  printf("+---------------------------------------------------------+\n"); 
//}

int main()
{
  Byte K [] = "This is one snazzy key ... I loooovvvee it."; 
  
  AezState state; 
  init(&state, K, strlen((const char *)K)); 

  Byte tag [1024] = "This is a really, really great tag.",
       message[1024] = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
       ciphertext[1024], plaintext [1024]; 
  unsigned msg_len = strlen((const char *)message),
           tag_len = strlen((const char *)tag), i; 

  /* Encipher(). */
  memset(ciphertext, 0, 1024); memset(plaintext, 0, 1024); 
  encipher(ciphertext, message, tag, msg_len, tag_len, &state); 
  decipher(plaintext, ciphertext, tag, msg_len, tag_len, &state); 

  printf("Ciphertext: "); 
  for (i = 0; i < msg_len; i++)
    printf("%02x", ciphertext[i]); 
  printf("\n"); 

  printf("Message:    "); 
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

