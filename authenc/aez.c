/**
 * aez.c -- AEZv2, a Caesar submission proposed by Viet Tung Hoang, Ted 
 * Krovetz, and Phillip Rogaway.
 *
 *   Written by Chris Patton <chrispatton@gmail.com>.
 *
 * This program is dedicated to the public domain. 
 *
 * To run benchmarks, compile with 
 *   gcc -Wall -O3 -std=c99 aez.c rijndael-alg-fst.c
 *
 * Last modified 22 Aug 2014. 
 */

#include "rijndael-alg-fst.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define INVALID -1 /* Reject plaintext (inauthentic). */ 

/* ----- AEZ context -------------------------------------------------------- */

typedef uint8_t Byte; 
typedef uint32_t Word; 

typedef union {
  Byte byte [16]; 
  Word word [4]; 
} Block; 

typedef struct {

  /* Key */ 
  Block K [11]; 

  /* Tweak context */
  Block L, Linit, J [8]; 

} Context; 


/* ---- Various primitives ------------------------------------------------- */ 

/*
 * rinjdael-alg-fst.{h,c} requires words in big endian byte order. 
 * set_big_endian() operates on 128-bit blocks. 
 */
#define reverse_u32(n) ( \
 ((n & 0x000000ffu) << 24) | \
 ((n & 0x0000ff00u) <<  8) | \
 ((n & 0x00ff0000u) >>  8) | \
 ((n & 0xff000000u) >> 24) \
)

#define set_big_endian(X) { \
  (X).word[0] = reverse_u32((X).word[0]); \
  (X).word[1] = reverse_u32((X).word[1]); \
  (X).word[2] = reverse_u32((X).word[2]); \
  (X).word[3] = reverse_u32((X).word[3]); \
}

#define cp_block(X, Y) { \
  (X).word[0] = (Y).word[0]; \
  (X).word[1] = (Y).word[1]; \
  (X).word[2] = (Y).word[2]; \
  (X).word[3] = (Y).word[3]; \
}

#define cp_bytes(dst, src, n) memcpy((Byte *)dst, (Byte *)src, n)

#define zero_block(X) { \
  (X).word[0] = 0; \
  (X).word[1] = 0; \
  (X).word[2] = 0; \
  (X).word[3] = 0; \
}

#define xor_block(X, Y, Z) { \
  (X).word[0] = (Y).word[0] ^ (Z).word[0]; \
  (X).word[1] = (Y).word[1] ^ (Z).word[1]; \
  (X).word[2] = (Y).word[2] ^ (Z).word[2]; \
  (X).word[3] = (Y).word[3] ^ (Z).word[3]; \
}


static void xor_bytes(Byte X [], const Byte Y [], const Byte Z [], unsigned n)
{
  for (int i = 0; i < 16; i++)
    X[i] = Y[i] ^ Z[i]; 
}

/*
 * Reverse byte order when computing tweaks. This is meant as an 
 * optimization for little endian systems. 
 */
static void rev_block(Byte X []) 
{
  Byte i, tmp[16];
  memcpy(tmp, X, 16);
  for (i=0; i<16; i++) X[i] = tmp[15-i];
}

/*
 * Multiply by two operation for key tweaking. 
 */
static void dot2(Byte *b) {
  rev_block(b); 
  Byte tmp = b[0];
  for (int i = 0; i < 15; i++)
    b[i] = (Byte)((b[i] << 1) | (b[i+1] >> 7));
  b[15] = (Byte)((b[15] << 1) ^ ((tmp >> 7) * 135));
  rev_block(b); 
}

/*
 * Incremental tweak generation. Used to precompute multiples of the tweaks. 
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
    dot2(Xs[2].byte);
  }

  else if (n & 1) // odd
  {
    cp_block(Xs[n], Xs[n-1]); 
    xor_block(Xs[n], Xs[n], Xs[1]);    
  }

  else // even
  {
    cp_block(Xs[n], Xs[n/2]);
    dot2(Xs[n].byte); 
  }
}


/* ----- AEZ initialization, Extract(), Expand()  --------------------------- */ 

static void extract(Block *J, Block *L, const Byte K [], unsigned key_bytes)
{
  unsigned i, j; 
  Block a[5], b[5], C[8], buff; 

  for (i = 0; i < 5; i++) 
  {
    for (j = 0; j < 16; j++)
      a[i].byte[j] = (Byte)j;
    set_big_endian(a[i]); 
  }
  
  zero_block(buff); 
  for (i = 0; i < 8; i++)
  {
    memset(C[i].byte, (Byte)i, 16); 
    rijndaelEncryptRound((uint32_t *)a, 10, C[i].byte, 4); 
  }

  zero_block(a[0]);   
  cp_block(a[1], C[1]); set_big_endian(a[1]); 
  cp_block(a[2], C[2]); set_big_endian(a[2]); 
  cp_block(a[3], C[3]); set_big_endian(a[3]); 
  zero_block(a[4]);

  zero_block(b[0]);
  cp_block(b[1], C[4]); set_big_endian(b[1]); 
  cp_block(b[2], C[5]); set_big_endian(b[2]); 
  cp_block(b[3], C[6]); set_big_endian(b[3]); 
  zero_block(b[4]);

  cp_block(C[2], C[7]); 
  cp_block(C[3], C[7]); dot2(C[3].byte); xor_block(C[3], C[3], C[2]); /* 3C */ 
  j = key_bytes - (key_bytes % 16); 
  zero_block(*J); zero_block(*L);
  for (i = 0; i < j; i += 16)
  {
    /* C = C[7], C[2] is the doubling version. 
     * C[0], C[1] are used as buffers. */
    xor_bytes(buff.byte, &K[i], C[2].byte, 16);
    cp_block(C[0], buff); rijndaelEncryptRound((uint32_t *)a, 10, C[0].byte, 4); 
    cp_block(C[1], buff); rijndaelEncryptRound((uint32_t *)b, 10, C[1].byte, 4); 
    xor_block(*J, *J, C[0]); 
    xor_block(*L, *L, C[1]); 
    dot2(C[2].byte); 
  }

  if (i < key_bytes) 
  {
    zero_block(buff);
    for (j = i; i < key_bytes; i++) 
      buff.byte[i - j] = K[i]; 
    buff.byte[i - j] = 0x80; 
    xor_block(buff, buff, C[3]); 
    cp_block(C[0], buff); rijndaelEncryptRound((uint32_t *)a, 10, C[0].byte, 4); 
    cp_block(C[1], buff); rijndaelEncryptRound((uint32_t *)b, 10, C[1].byte, 4); 
    xor_block(*J, *J, C[0]); 
    xor_block(*L, *L, C[1]); 
  }
  
  //printf("----Extract-----\n"); 
  //printf("Us: "); display_block(J); printf("\n");
  //printf("Us: "); display_block(L); printf("\n");
} // extract()

/* 
 * Expand extracted key (J, L) into AES4 key schedule.
 */
static void expand(Block Kshort[], const Block J, const Block L)
{
  unsigned i;
  Block k [5];

  cp_block(k[0], J);                
  cp_block(k[1], L);                
  cp_block(k[2], k[0]); dot2(k[2].byte); 
  cp_block(k[3], L);                
  cp_block(k[4], k[2]); dot2(k[4].byte); 
  set_big_endian(k[0]); 
  set_big_endian(k[1]); 
  set_big_endian(k[2]); 
  set_big_endian(k[3]); 
  set_big_endian(k[4]); 

  for (i = 0; i < 4; i++) 
  {
    memset(Kshort[i].byte, (Byte)i, 16); 
    rijndaelEncryptRound((uint32_t *)k, 10, Kshort[i].byte, 4); 
  }
  
  //printf("----Expand-----\n"); 
  //for (i = 0; i < 4; i++) { printf("Us: "); display_block(Kshort[i]); printf("\n"); }
  
} // expand() 

/*
 * Extract key material, set up key schedules and tweak context.  
 */
void init(Context *context, const Byte K [], unsigned key_bytes)
{
  unsigned i; 

  /* Get J, L, and key schedule from user key (K[4], K[5], K[6], K[7}). */ 
  extract(&context->J[1], &context->L, K, key_bytes); 
  expand(&context->K[4], context->J[1], context->L); 

  /* We need to be able to reset doubling L tweak. */ 
  cp_block(context->Linit, context->L);

  /* Precompute tweaks on J. */ 
  zero_block(context->J[0]); 
  for (i = 0; i < 8; i++)
    dot_inc(context->J, i); 

  /* Set up full key schedule. */
  cp_block(context->K[0],  context->L); // L 
  cp_block(context->K[1],  context->J[1]); // J
  cp_block(context->K[2],  context->K[1]); dot2(context->K[2].byte); // 2J
  cp_block(context->K[3],  context->K[2]); dot2(context->K[3].byte); // 4J
  cp_block(context->K[8],  context->K[4]); // K0
  cp_block(context->K[9],  context->K[5]); // K1
  cp_block(context->K[10], context->K[6]); // K2

  for (i = 0; i < 11; i++)
    set_big_endian(context->K[i])
  
  //printf("----Key schedule----\n"); 
  //for (i = 0; i < 11; i++) {printf("Us: "); display_block(context->K[i]); printf("\n");}
  
} // init() 


/* ---- E^{i,j}_k(), the tweakable blockcipher ----------------------------- */

/*
 * A tweakable blockcipher with two parameters. `i` determines the key 
 * schedule and number of rounds for the AES4 call, and is any of {-1, 0, 1, 
 * 2, 3}. -1 signals standard 10-round AES. `j` actually corresponds to a point in
 * a two parameter tweak set, the first of which is a residue mod 8, the other 
 * doubling whenever 0 = j mod 8. Doubling is handled by variant() and reset().
 */ 
static void E(Byte C [], const Byte M [], int i, int j, Context *context)
{
  Block tmp, *Kshort; 
  //printf("----Blockcipher (%d, %d)----\n", i, j); 
  if (i == -1) /* 0 <= j < 8 */ 
  {
    xor_bytes(C, M, context->J[j % 8].byte, 16);
    rijndaelEncrypt((uint32_t *)context->K, 10, C, C); 
  }

  else if (i == 0 || j == 0) /* 0 <= j < 8 */ 
  {
    xor_bytes(C, M, context->J[j % 8].byte, 16);
    Kshort = &(context->K[4 + i]); 
    cp_block(tmp, Kshort[4]); zero_block(Kshort[4]); 
    rijndaelEncryptRound((uint32_t *)Kshort, 10, C, 4); 
    cp_block(Kshort[4], tmp); 
  }

  else 
  {
    xor_bytes(C, M, context->J[j % 8].byte, 16); 
    xor_bytes(C, C, context->L.byte, 16); 
    Kshort = &(context->K[4 + i]); 
    cp_block(tmp, Kshort[4]); zero_block(Kshort[4]); 
    rijndaelEncryptRound((uint32_t *)Kshort, 10, C, 4); 
    cp_block(Kshort[4], tmp); 
  }
} // E() 


static void fella(Block *C, const Block M, int i, int j, Context *context)
{
  Block tmp, *Kshort; 
  //printf("----Blockcipher (%d, %d)----\n", i, j); 
  if (i == -1) /* 0 <= j < 8 */ 
  {
    xor_block(*C, M, context->J[j % 8]);
    rijndaelEncrypt((uint32_t *)context->K, 10, C->byte, C->byte); 
  }

  else if (i == 0 || j == 0) /* 0 <= j < 8 */ 
  {
    xor_block(*C, M, context->J[j % 8]);
    Kshort = &(context->K[4 + i]); 
    cp_block(tmp, Kshort[4]); zero_block(Kshort[4]); 
    rijndaelEncryptRound((uint32_t *)Kshort, 10, C->byte, 4); 
    cp_block(Kshort[4], tmp); 
  }

  else 
  {
    xor_block(*C, M, context->J[j % 8]); 
    xor_block(*C, *C, context->L); 
    Kshort = &(context->K[4 + i]); 
    cp_block(tmp, Kshort[4]); zero_block(Kshort[4]); 
    rijndaelEncryptRound((uint32_t *)Kshort, 10, C->byte, 4); 
    cp_block(Kshort[4], tmp); 
  }
} // E() 
/*
 * Update doubling tweak `T` if necessary. `i` doesn't actually
 * have an affect on the tweak. 
 */
static void variant(Context *context, int i, int j) 
{
  if (j > 8 && (j - 1) % 8 == 0)
    dot2(context->L.byte); 
}

/*
 * Reset tweak. 
 */
static void reset(Context *context)
{
  cp_block(context->L, context->Linit);
}


/* ---- AHash() ------------------------------------------------------------ */ 

/*
 * An XOR-almust-universal hash function based on AES4. Output length of `H` 
 * is 128 bits. `M` is an arbitrary length byte string of length `msg_bytes`. 
 */

void ahash(Byte H [], const Byte M [], unsigned msg_bytes, Context *context)
{
  Block buff, sigma; 
  unsigned i, j = 0, k = msg_bytes - (msg_bytes % 16);  
  
  reset(context); 
  zero_block(sigma); 

  /* Unfragmented blocks. */ 
  for (i = 0; i < k; i += 16)
  {
    cp_bytes(buff.byte, &M[i], 16); 
    fella(&buff, buff, 3, j, context);  
    xor_block(sigma, sigma, buff);
    variant(context, 0, ++j); 
  }

  /* Fragmented last block. */
  if (i < msg_bytes || i == 0) 
  {
    zero_block(buff); 
    cp_bytes(buff.byte, &M[i], msg_bytes - i); 
    buff.byte[msg_bytes - i] = 0x80;
    fella(&buff, buff, 1, 0, context); 
    xor_block(sigma, sigma, buff); 
  }
  
  cp_bytes(H, sigma.byte, 16); 
  reset(context); 
} // AHash()


/* ---- AMac() ------------------------------------------------------------- */

/*
 * A secure message authentication code based on AHash(). Output length of `T`
 * is 128 bits. `M` is an arbitrary length byte string of length `msg_bytes`. 
 */

void amac(Byte T [], const Byte M [], unsigned msg_bytes, Context *context)
{
  Block tmp; /* FIXME This is not so nice. ahash() 
                should probalby output to a `Block`. */  
  ahash(T, M, msg_bytes, context); 
  cp_bytes(tmp.byte, T, 16); 
  fella(&tmp, tmp, -1, 5, context); 
  cp_bytes(T, tmp.byte, 16); 
} // AMac() 


/* ---- Encipher(), Decipher() ---------------------------------------------- */

/*
 * EncipherEME4, the meat of AEZv2. If `inv` == 0, then `M` is taken to be a 
 * plaintext and is encrypted; If `inv` == 1, then `M` is taken to be a 
 * ciphertext and is decrypted. Warning: only 0 and 1 are valid values of 
 * `inv`. 
 */ 
void encipher_eme4(Byte C [], 
                   const Byte M [], 
                   const Byte T [], 
                   unsigned msg_bytes,
                   unsigned tag_bytes, 
                   unsigned inv,
                   Context *context)
{
  Block buff, delta, X, Y, Z, 
        R0 /* R */, R1 /* R' */, 
        S, Y0, Y1, M0, M1, C0, C1; 
  unsigned i, j, k = msg_bytes - (msg_bytes % 32);  
  
  ahash(delta.byte, T, tag_bytes, context);
  zero_block(X); 

  /* X; X1, X'1, ... Xm, X'm */ 
  reset(context); 
  for (j = 1, i = 32; i < k; i += 32)
  {
    /* M = &M[i], M' = &M[i+16] */
    cp_bytes(M0.byte, &M[i], 16);  cp_bytes(M1.byte, &M[i+16], 16); 
    
    fella(&C1, M1, 1, j, context); xor_block(C1, C1, M0); 
    fella(&C0, C1, 0, 0, context); xor_block(C0, C0, M1); 
  
    xor_block(X, X, C0); variant(context, 0, ++j); 
   
    cp_bytes(&C[i], C0.byte, 16), cp_bytes(&C[i+16], C1.byte, 16); 
  }

  if (msg_bytes - i >= 16) /* M*, M** */
  {
    cp_bytes(buff.byte, &M[i], 16); 
    fella(&buff, buff, 0, 3, context); 
    xor_block(X, X, buff); 
  
    zero_block(buff); i += 16;  
    cp_bytes(buff.byte, &M[i], msg_bytes - i); 
    buff.byte[msg_bytes - i] = 0x80; 
    fella(&buff, buff, 0, 4, context); 
    xor_block(X, X, buff); 
  }
  
  else if (msg_bytes - i > 0) /* M* */ 
  { 
    zero_block(buff); 
    cp_bytes(buff.byte, &M[i], msg_bytes - i); 
    buff.byte[msg_bytes - i] = 0x80; 
    fella(&buff, buff, 0, 3, context); 
    xor_block(X, X, buff); 
  }

  /* R, R'; S */ 
  xor_bytes(R0.byte, X.byte, &M[16], 16);
  fella(&R0, R0, 0, 1 + inv, context); 
  xor_bytes(R0.byte, R0.byte, M, 16); 
  xor_block(R0, R0, delta); // R

  fella(&R1, R0, -1, 1 + inv, context); 
  xor_bytes(R1.byte, R1.byte, &M[16], 16); 
  xor_block(R1, R1, X); // R' 

  xor_block(S, R0, R1); // S
  zero_block(Y);
  
  /* Y; C1, C'1, ... Cm, C'm */ 
  reset(context); 
  for (j = 1, i = 32; i < k; i += 32)
  {
    cp_bytes(M0.byte, &C[i], 16); cp_bytes(M1.byte, &C[i+16], 16); 
    
    /* X = &C[i], X' = &C[i+16]; Y0 = Yi, Y1 = Y'i*/ 
    fella(&Z, S, 2, j, context);
    
    xor_block(Y0, M1, Z); xor_block(Y1, M0, Z);
    
    fella(&C1, Y1, 0, 0, context); xor_block(C1, C1, Y0); 
    fella(&C0, C1, 1, j, context); xor_block(C0, C0, Y1); 

    xor_block(Y, Y, Y0); variant(context, 0, ++j); 

    cp_bytes(&C[i], C0.byte, 16); cp_bytes(&C[i+16], C1.byte, 16); 
  }
  
  if (msg_bytes - i >= 16) /* C*, C** */ 
  {
    fella(&buff, S, -1, 3, context); 
    xor_bytes(&C[i], &M[i], buff.byte, 16); 
    cp_bytes(buff.byte, &C[i], 16); 
    fella(&buff, buff, 0, 3, context); 
    xor_block(Y, Y, buff); 
    
    i += 16; 
    fella(&buff, S, -1, 4, context); 
    for (j = i; i < msg_bytes; i++) 
      C[i] = M[i] ^ buff.byte[i - j];
    
    i = j;
    zero_block(buff); 
    for (j = i; i < msg_bytes; i++) 
      buff.byte[i - j] = C[i]; 
    buff.byte[i - j] = 0x80; 
    fella(&buff, buff, 0, 4, context); 

    xor_block(Y, Y, buff); 
  }
  
  else if (msg_bytes - i > 0) /* C* */ 
  {
    fella(&buff, S, -1, 3, context);
    for (j = i; i < msg_bytes; i++) 
      C[i] = M[i] ^ buff.byte[i - j];
    
    i = j;
    zero_block(buff); 
    for (j = i; i < msg_bytes; i++) 
      buff.byte[i - j] = C[i]; 
    buff.byte[i - j] = 0x80; 
    fella(&buff, buff, 0, 3, context); 

    xor_block(Y, Y, buff); 
  }

  fella(&buff, R1, -1, 2 - inv, context); 
  xor_block(C1, R0, buff); 

  fella(&C0, C1, 0, 2 - inv, context);
  xor_block(C0, C0, R1); 
  xor_bytes(C, C0.byte, delta.byte, 16); 
  xor_bytes(&C[16], C1.byte, Y.byte, 16); 

  reset(context); 
} // EncipherEME4()


/*
 * Only-even-cycles correction for FF0.
 */
static void point_swap(Byte C [], 
                       const Block delta, 
                       unsigned msg_bytes,
                       Context *context)
{
  unsigned i; 
  Block buff; 
  zero_block(buff); 
  for (i = 0; i < msg_bytes; i++)
    buff.byte[i] = C[i]; 
  buff.byte[0] |= 0x80; 
  xor_block(buff, buff, delta); 
  E(buff.byte, buff.byte, 0, 7, context); 
  C[0] ^= (buff.byte[0] & 0x80);  
}

/*
 * EncipherFF0() -- scheme for small messages (< 32). There are no 
 * provable security results for this scheme ... the number of 
 * Feistel round depends on the message length and is chosen 
 * heurestically. The code is derived from Ted Krovetz' reference
 * implementation of AEZv1. 
 */
void encipher_ff0(Byte C [], 
                  const Byte M [], 
                  const Byte T [], 
                  unsigned msg_bytes,
                  unsigned tag_bytes, 
                  unsigned inv,
                  Context *context)
{
  int i, j, k, l, n = msg_bytes / 2;
  Block delta, front, back;
  Byte mask=0x00, pad=0x80, ctr,
       buff [32], *A, *B;  
  
  if (msg_bytes == 1)      k = 24; 
  else if (msg_bytes == 2) k = 16;
  else if (msg_bytes < 16) k = 10; 
  else                     k = 8;

  if (msg_bytes >= 16) j = 5; 
  else                 j = 6; 

  ahash(delta.byte, T, tag_bytes, context); 
  l = (msg_bytes + 1) / 2; 
  memcpy(C, M, msg_bytes);

  if (inv && msg_bytes < 16) 
    point_swap(C, delta, msg_bytes, context); 

  memcpy(front.byte, C, l); 
  memcpy(back.byte, &C[n], l); 

  if (msg_bytes & 1)
  {
    for (i = 0; i < n; i++)
      back.byte[i] = (Byte)((back.byte[i] << 4) | (back.byte[i+1] >> 4));
    back.byte[n] = (Byte)(back.byte[n] << 4);
    pad = 0x08; mask = 0xf0;
  }

  if (inv) { B = front.byte; A = back.byte; ctr = k - 1; } 
  else     { A = front.byte; B = back.byte; ctr = 0; }

  for (i = 0; i < k; i += 2)
  {
    memset(buff, 0, 16); // zero_block(buff); FIXME
    memcpy(buff, B, l);
    buff[n] = (buff[n] & mask) | pad; 
    xor_bytes(buff, buff, delta.byte, 16);
    buff[0] ^= ctr; 
    E(buff, buff, 0, j, context); 
    xor_bytes(A, A, buff, 16); 
    if (!inv) ++ctr;
    else      --ctr; 

    memset(buff, 0, 16); // zero_block(buff); FIXME
    memcpy(buff, A, l); 
    buff[n] = (buff[n] & mask) | pad; 
    xor_bytes(buff, buff, delta.byte, 16);
    buff[0] ^= ctr; 
    E(buff, buff, 0, j, context); 
    xor_bytes(B, B, buff, 16); 
    if (!inv) ++ctr;
    else      --ctr; 
  }
    
  memcpy(buff, front.byte, n);
  memcpy(&buff[n], back.byte, l);
  if (msg_bytes & 1) 
  {
    for (i = msg_bytes - 1; i > n; i--)
       buff[i] = (Byte)((buff[i] >> 4) | (buff[i-1] << 4));
     buff[n] = (Byte)((back.byte[0] >> 4) | (front.byte[n] & mask));
  }
  memcpy(C, buff, msg_bytes);
  
  if (!inv && msg_bytes < 16) 
    point_swap(C, delta, msg_bytes, context);  
} // EncipherFF0() 

/*
 * AEZ enciphering. If |M| < 32, use FF0; otherwise, use EME4. 
 */
void encipher(Byte C [], 
              const Byte M [], 
              const Byte T [], 
              unsigned msg_bytes,
              unsigned tag_bytes, 
              Context *context)
{
  if (msg_bytes < 32) 
    encipher_ff0(C, M, T, msg_bytes, tag_bytes, 0, context); 
  else
    encipher_eme4(C, M, T, msg_bytes, tag_bytes, 0, context); 
}

/*
 * AEZ deciphering. 
 */
void decipher(Byte M [], 
              const Byte C [], 
              const Byte T [], 
              unsigned msg_bytes,
              unsigned tag_bytes, 
              Context *context)
{
  if (msg_bytes < 32) 
    encipher_ff0(M, C, T, msg_bytes, tag_bytes, 1, context); 
  else
    encipher_eme4(M, C, T, msg_bytes, tag_bytes, 1, context); 
}


/* ----- Encrypt(), Decrypt(), Format() ------------------------------------- */

/*
 * Format nonce `N` and additional data `A`. Dynamically allocate an 
 * appropriate size buffer and assign it to `tag`; return the number of
 * bytes in the buffer. (Caller should free `tag`.) Copied from the 
 * reference implementation of AEZv1. 
 */
unsigned format(Byte *T [], 
                const Byte N[],
                const Byte A[],
                unsigned nonce_bytes,
                unsigned data_bytes,
                unsigned auth_bytes)
{
    unsigned tag_bytes; 
    if (nonce_bytes <= 12) {
        Byte *res = (Byte *)malloc(data_bytes+16);
        memset(res,0,16);
        res[0] = (Byte)(nonce_bytes == 12 ? auth_bytes | 0x40 : auth_bytes);
        memcpy(res+4, N, nonce_bytes);
        if (nonce_bytes < 12) res[nonce_bytes+4] = 0x80;
        memcpy(res+16, A, data_bytes);
        tag_bytes = data_bytes+16;
        *T = res;
    } else {
        unsigned pdata_bytes = 16 - (data_bytes % 16);
        Byte *res = (Byte *)malloc(12+nonce_bytes+data_bytes+pdata_bytes);
        res[0] = (Byte)(auth_bytes | 0x80);
        res[1] = res[2] = res[3] = 0;
        memcpy(res+4, N, 12);
        memcpy(res+16, A, data_bytes);
        res[16+data_bytes] = 0x80;
        memset(res+16+data_bytes+1,0,pdata_bytes-1);
        memcpy(res+16+data_bytes+pdata_bytes,N+12,nonce_bytes-12);
        memset(res+4+nonce_bytes+data_bytes+pdata_bytes, 0, 4);
        res[8+nonce_bytes+data_bytes+pdata_bytes] = (Byte)(nonce_bytes >> 24);
        res[9+nonce_bytes+data_bytes+pdata_bytes] = (Byte)(nonce_bytes >> 16);
        res[10+nonce_bytes+data_bytes+pdata_bytes] = (Byte)(nonce_bytes >> 8);
        res[11+nonce_bytes+data_bytes+pdata_bytes] = (Byte)nonce_bytes;
        tag_bytes = 12+nonce_bytes+data_bytes+pdata_bytes;
        *T = res;
    }
  return tag_bytes;
} // Format() 

#define MAX(a, b) (a < b) ? b : a

/*
 * AEZ encryption. The length of the ciphertext (`C`) will be the length of
 * the input message plus the length of the authentication code (`auth_bytes`). 
 * `C` is expected to be at least max(msg_bytes + auth_bytes, 16), where 
 * auth_bytes <= 16. 
 */
int encrypt(Byte C [], 
            const Byte M [], 
            const Byte N [], 
            const Byte A [], 
            unsigned msg_bytes, 
            unsigned nonce_bytes, 
            unsigned data_bytes, 
            unsigned auth_bytes, 
            Context *context)
{
  Byte *T, *X = malloc(MAX(msg_bytes + auth_bytes, 16)); 
  unsigned tag_bytes = format(&T, N, A, nonce_bytes, data_bytes, auth_bytes); 
  
  //printf("Our tag: "); 
  //for (unsigned i = 0; i < tag_bytes; i++)
  //  printf("%02x", T[i]); 

  if (msg_bytes == 0)
  {
    amac(X, T, tag_bytes, context); 
    memcpy(C, X, auth_bytes); 
  }

  else
  {
    memcpy(X, M, msg_bytes); 
    memset(&X[msg_bytes], 0, auth_bytes);
    encipher(C, X, T, msg_bytes + auth_bytes, tag_bytes, context); 
  }

  free(X); free(T); 
  return msg_bytes + auth_bytes;
} // Encrypt(); 

/*
 * AEZ decryption. `msg_bytes` should be the length of the enciphered message 
 * and message authenticaiton code (output of aez_encrypt()). If the MAC is 
 * correct, then the plaintext is copied to `out` (This is expected to be at 
 * least msg_bytes - auth_bytes long.) Otherwise the plaintext is witheld and
 * the function returns -1.
 */
int decrypt(Byte M [], 
            const Byte C [], 
            const Byte N [], 
            const Byte A [], 
            unsigned msg_bytes, 
            unsigned nonce_bytes, 
            unsigned data_bytes, 
            unsigned auth_bytes, 
            Context *context)
{
  int res = msg_bytes - auth_bytes;  
  Byte *T, *X = malloc(MAX(msg_bytes, 16)); 
  unsigned i, tag_bytes = format(&T, N, A, nonce_bytes, data_bytes, auth_bytes); 
  
  if (msg_bytes == auth_bytes)
  {
    amac(X, T, tag_bytes, context); 
    for (i = 0; i < msg_bytes; i++)
      if (X[i] != C[i])
        res = INVALID;  
  }

  else 
  {
    decipher(X, C, T, msg_bytes, tag_bytes, context); 
    for (i = msg_bytes - auth_bytes; i < msg_bytes; i++)
      if (X[i] != 0)
        res = INVALID; 
  } 

  if (res != INVALID)
    memcpy(M, X, msg_bytes - auth_bytes); 
    
  free(X); free(T); 
  return res;
} // Decrypt() 



/* ----- Testing, testing ... ---------------------------------------------- */

#include <time.h>
#include <stdio.h>

static void display_block(const Block X) 
{
  for (int i = 0; i < 4; i ++)
    printf("0x%08x ", X.word[i]); 
}

//static void display_context(Context *context)
//{
//  unsigned i; 
//  printf("+-----------------------------------------------------+\n"); 
//  for (i = 0; i < 11; i++)
//  {
//    printf("| K[%-2d] = ", i); 
//    display_block(context->K[i]); 
//    printf("|\n"); 
//  }
//
//  printf("+-----------------------------------------------------+\n"); 
//  for (i = 0; i < 8; i++)
//  {
//    printf("| J[%-2d] = ", i); 
//    display_block(context->J[i]); 
//    printf("|\n"); 
//  }
//
//  printf("+-----------------------------------------------------+\n"); 
//  printf("| L     = "); 
//  display_block(context->L); 
//  printf("|\n"); 
//  
//  printf("| Linit = "); 
//  display_block(context->Linit); 
//  printf("|\n"); 
//  printf("+-----------------------------------------------------+\n"); 
//}

#define HZ (2.9e9) 
#define TRIALS 100000

void benchmark() {

  static const int msg_len [] = {64,     128,  256,   512, 
                                 1024,   4096, 10000, 100000,
                                 1000000}; 
  static const int num_msg_lens = 6; 
  unsigned i, j, auth_bytes = 16, key_bytes = 16; 
  
  Context context; 
  Block key;   memset(key.byte, 0, 16); 
  Block nonce; memset(nonce.byte, 0, 16); 
  init(&context, key.byte, key_bytes);

  Byte *message = malloc(auth_bytes + msg_len[num_msg_lens-1]); 
  Byte *ciphertext = malloc(auth_bytes + msg_len[num_msg_lens-1]); 
  Byte *plaintext = malloc(auth_bytes + msg_len[num_msg_lens-1]); 

  clock_t t; 
  double total_cycles; 
  double total_bytes; 

  for (i = 0; i < num_msg_lens; i++)
  {
    t = clock(); 
    for (j = 0; j < TRIALS; j++)
    {
      encrypt(ciphertext, message, nonce.byte, NULL, 
                  msg_len[i], 16, 0, auth_bytes, &context); 
      nonce.word[0] ++; 
    }
    t = clock() - t; 
    total_cycles = t * HZ / CLOCKS_PER_SEC; 
    total_bytes = (double)TRIALS * msg_len[i]; 
    printf("%8d bytes, %.2f cycles per byte\n", msg_len[i], 
                               total_cycles/total_bytes); 
  }
  
  //ciphertext[343] = 'o';
  nonce.word[0] --; i --; 
  if (decrypt(plaintext, ciphertext, nonce.byte, NULL, 
               msg_len[i] + auth_bytes, 16, 0, auth_bytes, &context) != INVALID)
    printf("Success! ");
  else 
    printf("Tag mismatch. ");
  printf("\n"); 

  free(message); 
  free(ciphertext); 
  free(plaintext); 
}

  
void verify() 
{
  Byte  key [] = "One day we will.", nonce [] = "Things are occuring!"; 
  
  Block sum; 
  memset(sum, 0, 16); 

  unsigned key_bytes = strlen((const char *)key), 
           nonce_bytes = strlen((const char *)nonce), 
           auth_bytes = 3, i, res, msg_len = 10001; 

  Byte *message = malloc(auth_bytes + msg_len); 
  Byte *ciphertext = malloc(auth_bytes + msg_len); 
  Byte *plaintext = malloc(auth_bytes + msg_len); 
  memset(ciphertext, 0, 1024); 
  memset(message, 0, 1024); 
  
  Context context; 
  init(&context, key, key_bytes); 
  //display_context(&context); 
  for (i = 0; i < msg_len/*max length*/; i++)
  {
    encrypt(ciphertext, message, nonce, nonce, 
                i, nonce_bytes, nonce_bytes, auth_bytes, &context); 
    xor_bytes(sum.byte, sum.byte, ciphertext, 16); 
  
    res = decrypt(plaintext, ciphertext, nonce, nonce, 
           i + auth_bytes, nonce_bytes, nonce_bytes, auth_bytes, &context); 

    if (res == INVALID || memcmp(plaintext, message, i) != 0)
      printf("msg length %d: plaintext mismatch!\n", i + auth_bytes); 
  }
  display_block(sum); printf("\n");
  free(message); 
  free(ciphertext); 
  free(plaintext); 
}

int main()
{
  verify();  
  benchmark(); 
  return 0; 
}
