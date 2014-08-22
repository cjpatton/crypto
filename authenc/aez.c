/**
 * aez.c -- AEZv2, a Caesar submission proposed by Viet Tung Hoang, Ted 
 * Krovetz, and Phillip Rogaway. This implementation conforms to the 
 * specification except on one point; in the tweak computation, we don't 
 * reverse the byte order. 
 *
 *   Written by Chris Patton <chrispatton@gmail.com>.
 *
 * This program is dedicated to the public domain. 
 *
 * To run benchmarks, compile with 
 *   gcc -Wall -O3 -std=c99 aez.c rijndael-alg-fst.c
 *
 * Last modified 21 Aug 2014. 
 */

#include "rijndael-alg-fst.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define INVALID -1 /* Reject plaintext (inauthentic). */ 
#define ALIGN(n) __attribute__ ((aligned(n)))

/* ----- AEZ context -------------------------------------------------------- */

typedef unsigned char Byte; 
typedef Byte Block [16]; 

typedef struct {

  /* Key */ 
  Block Klong [11]; 

  /* Tweak context */
  Block L, Linit, J [8]; 

} Context; 


/* ---- Various primitives ------------------------------------------------- */ 

/*
 * rinjdael-alg-fst.{h,c} requires words in big endian byte order. 
 * set_big_endian() operates on 128-bit blocks. 
 */
#define reverse_u32(dst, src) { \
  (dst)[0] = (src)[3]; \
  (dst)[1] = (src)[2]; \
  (dst)[2] = (src)[1]; \
  (dst)[3] = (src)[0]; }

#define u8_ptr(X) ((uint8_t *)X)
#define u32_ptr(X) ((uint32_t *)X) 

#define set_big_endian(X) { \
  reverse_u32(&u8_ptr(X)[0],  &u8_ptr(X)[0]); \
  reverse_u32(&u8_ptr(X)[4],  &u8_ptr(X)[4]); \
  reverse_u32(&u8_ptr(X)[8],  &u8_ptr(X)[8]); \
  reverse_u32(&u8_ptr(X)[12], &u8_ptr(X)[12]); \
}

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
 *        done for efficient implemenation on little endian systems. 
 */
static void dot2(Byte *b) {
  Byte tmp = b[0];
  for (int i = 0; i < 15; i++)
    b[i] = (Byte)((b[i] << 1) | (b[i+1] >> 7));
  b[15] = (Byte)((b[15] << 1) ^ ((tmp >> 7) * 135));
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

static void extract(Block J, Block L, const Byte K [], unsigned key_bytes)
{
  unsigned i, j; 
  Block a[5], b[5], C[8], buff; 

  for (i = 0; i < 5; i++) 
  {
    for (j = 0; j < 16; j++)
      a[i][j] = (Byte)j;
    set_big_endian(a[i]); 
  }

  zero_block(buff); 
  for (i = 0; i < 7; i++)
  {
    buff[0] ++; 
    rijndaelEncrypt((uint32_t *)a, 4, buff, C[i]); 
  }

  zero_block(a[0]);     set_big_endian(a[0]); 
  cp_block(a[1], C[0]); set_big_endian(a[1]); 
  cp_block(a[2], C[1]); set_big_endian(a[2]); 
  cp_block(a[3], C[2]); set_big_endian(a[3]); 
  zero_block(a[4]); 

  zero_block(b[0]);     set_big_endian(b[0]); 
  cp_block(b[1], C[3]); set_big_endian(b[1]); 
  cp_block(b[2], C[4]); set_big_endian(b[2]); 
  cp_block(b[3], C[5]); set_big_endian(b[3]); 
  zero_block(b[4]);

  cp_block(C[2], C[6]); 
  j = key_bytes - (key_bytes % 16); 
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

  if (i < key_bytes) 
  {
    zero_block(buff);
    for (j = i; i < key_bytes; i++) 
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
 * Expand extracted key (J, L) into AES4 key schedule.
 */
static void expand(Block Kshort[], const Block J, const Block L)
{
  unsigned i;
  Block k [5], buff;

  cp_block(k[0], J);                set_big_endian(k[0]); 
  cp_block(k[1], L);                set_big_endian(k[1]); 
  cp_block(k[2], k[0]); dot2(k[2]); set_big_endian(k[2]); 
  cp_block(k[3], L);                set_big_endian(k[3]); 
  cp_block(k[4], k[2]); dot2(k[4]); set_big_endian(k[4]); 
  zero_block(k[5]); 

  zero_block(Kshort[4]); 
  zero_block(buff);
  for (i = 0; i < 4; i++) 
  {
    buff[0] ++; 
    rijndaelEncrypt((uint32_t *)k, 4, buff, Kshort[i]); 
    set_big_endian(Kshort[i]); 
  }
} // expand() 

/*
 * Extract key material, set up key schedules and tweak context.  
 */
void init(Context *context, const Byte K [], unsigned key_bytes)
{
  unsigned i; 

  /* Get J, L, and key schedule from user key. */ 
  extract(context->J[1], context->L, K, key_bytes); 
  expand(&(context->Klong[4]), context->J[1], context->L); 

  /* We need to be able to reset doubling L tweak. */ 
  cp_block(context->Linit, context->L);

  /* Precompute tweaks on J. */ 
  zero_block(context->J[0]); 
  for (i = 0; i < 8; i++)
    dot_inc(context->J, i); 

  /* Set up full key schedule. */
  cp_block(context->Klong[0],  context->L);    
  set_big_endian(context->Klong[0]); // L
  cp_block(context->Klong[1],  context->J[1]); 
  set_big_endian(context->Klong[1]); // J
  cp_block(context->Klong[2],  context->Klong[1]); 
  dot2(context->Klong[2]); set_big_endian(context->Klong[2]); // 2J
  cp_block(context->Klong[3],  context->Klong[2]); 
  dot2(context->Klong[3]); set_big_endian(context->Klong[3]); // 4J
  cp_block(context->Klong[8],  context->Klong[4]); // K0
  cp_block(context->Klong[9],  context->Klong[5]); // K1
  cp_block(context->Klong[10], context->Klong[6]); // K2
} // init() 


/* ---- E^{i,j}_k(), the tweakable blockcipher ----------------------------- */

/*
 * A tweakable blockcipher with two parameters. `i` determines the key 
 * schedule and number of rounds for the AES4 call, and is any of {-1, 0, 1, 
 * 2, 3}. -1 signals standard 10-round AES. `j` actually corresponds to a point in
 * a two parameter tweak set, the first of which is a residue mod 8, the other 
 * doubling whenever 0 = j mod 8. Doubling is handled by variant() and reset().
 */ 
static void cipher(Byte C [], const Byte M [], int i, int j, Context *context)
{
  if (i == -1) /* 0 <= j < 8 */ 
  {
    xor_block(C, M, context->J[j]); 
    rijndaelEncrypt((uint32_t *)context->Klong, 10, C, C); 
  }

  else if (i == 0 || j == 0) /* 0 <= j < 8 */ 
  {
    xor_block(C, M, context->J[j]); 
    rijndaelEncryptRound((uint32_t *)&(context->Klong[4]), 10, C, 4); 
  }

  else 
  {
    xor_block(C, M, context->J[j % 8]); 
    xor_block(C, C, context->L); 
    rijndaelEncryptRound((uint32_t *)&(context->Klong[4]), 10, C, 4); 
  }
} // cipher() 

/*
 * Update doubling tweak `T` if necessary. `i` doesn't actually
 * have an affect on the tweak. 
 */
static void variant(Context *context, int i, int j) 
{
  if (j % 8 == 0)
    dot2(context->L); 
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
  Byte buff [16]; 
  unsigned i, j = 0, k = msg_bytes / 16;  
  
  reset(context); 
  zero_block(H); 

  /* Unfragmented blocks. */ 
  for (i = 0; i < k * 16; i += 16)
  {
    variant(context, i, ++j); 
    cipher(buff, &M[i], 3, j, context);  
    xor_block(H, H, buff); 
  }

  /* Fragmented last block. */
  if (i < msg_bytes || i == 0) 
  {
    k = i; 
    for (; i < msg_bytes; i++)
      buff[i - k] = M[i]; 
    buff[i - k] = 0x80;
    cipher(buff, buff, 0, 1, context); 
    xor_block(H, H, buff); 
  }
  
  reset(context); 
} // AHash()


/* ---- AMac() ------------------------------------------------------------- */

/*
 * A secure message authentication code based on AHash(). Output length of `T`
 * is 128 bits. `M` is an arbitrary length byte string of length `msg_bytes`. 
 */

void amac(Byte T [], const Byte M [], unsigned msg_bytes, Context *context)
{
  ahash(T, M, msg_bytes, context); 
  cipher(T, T, -1, 5, context); 
} // AMac() 


/* ---- Encipher(), Decipher() ---------------------------------------------- */

/*
 * EncipherEME4, the meat of AEZv2. 
 */ 
void encipher_eme4(Byte C [], 
                   const Byte M [], 
                   const Byte T [], 
                   unsigned msg_bytes,
                   unsigned tag_bytes, 
                   unsigned inv,
                   Context *context)
{
  Block buff, delta, X, Y, Z, R0 /* R */, R1 /* R' */, S, Y0, Y1; 
  unsigned i, j, k = msg_bytes / 32;  
  
  ahash(delta, T, tag_bytes, context);
  zero_block(X); 

  /* X; X1, X'1, ... Xm, X'm */ 
  reset(context); 
  for (j = 0, i = 32; i < k * 32; i += 32)
  {
    /* M = &M[i], M' = &M[i+16] */ 
    variant(context, i, ++j); 
    cipher(&C[i+16], &M[i+16], 1, j, context); 
    xor_block(&C[i+16], &C[i+16], &M[i]); 

    cipher(&C[i], &C[i+16], 0, 0, context); 
    xor_block(&C[i], &C[i], &M[i+16]); 

    xor_block(X, X, &C[i]); 
  }

  if (msg_bytes - i > 0 && msg_bytes - i < 16) /* M* */ 
  {
    zero_block(buff); 
    for (j = i; i < msg_bytes; i++)
      buff[i - j] = M[i]; 
    buff[i - j] = 0x80; 
    cipher(buff, buff, 0, 3, context); 
    
    for (j = i; i < msg_bytes; i++)
      X[i - j] ^= buff[i - j];
  }
  
  else if (msg_bytes - i > 0) /* M*, M** */
  {
    cipher(buff, &M[i], 0, 3, context); 
    xor_block(X, X, buff); 
  
    i += 16; 
    zero_block(buff); 
    for (j = i; i < msg_bytes; i++)
      buff[i - j] = M[i]; 
    buff[i - j] = 0x80; 
    cipher(buff, buff, 0, 4, context); 
    
    for (j = i; i < msg_bytes; i++)
      X[i - j] ^= buff[i - j];
  }

  /* R, R'; S */ 
  xor_block(R0, X, &M[16]);
  if (!inv) cipher(R0, R0, 0, 1, context); 
  else      cipher(R0, R0, 0, 2, context); 
  xor_block(R0, R0, M); 
  xor_block(R0, R0, delta); // R

  if (!inv) cipher(R1, R0, -1, 1, context); 
  else      cipher(R1, R0, -1, 2, context); 
  xor_block(R1, R1, &M[16]); 
  xor_block(R1, R1, X); // R' 

  xor_block(S, R0, R1); // S
  zero_block(Y);

  /* Y; C1, C'1, ... Cm, C'm */ 
  reset(context); 
  for (j = 0, i = 32; i < k * 32; i += 32)
  {
    variant(context, i, ++j); 

    /* X = &C[i], X' = &C[i+16]; Y0 = Yi, Y1 = Y'i*/ 
    cipher(Z, S, 2, j, context); 
    xor_block(Y0, &C[i+16], Z);
    xor_block(Y1, &C[i], Z);
    
    cipher(&C[i+16], Y1, 0, 0, context); 
    xor_block(&C[i+16], &C[i+16], Y0); 

    cipher(&C[i], &C[i+16], 1, j, context); 
    xor_block(&C[i], &C[i], Y1); 

    xor_block(Y, Y, Y0); 
  }
  
  if (msg_bytes - i > 0 && msg_bytes - i < 16) /* C* */ 
  {
    cipher(buff, S, -1, 3, context); 
    for (j = i; i < msg_bytes; i++) 
      C[i] = M[i] ^ buff[i - j];
    
    zero_block(buff); 
    for (j = i; i < msg_bytes; i++) 
      buff[i - j] = C[i]; 
    buff[i - j] = 0x80; 
    cipher(buff, buff, 0, 3, context); 

    for (j = i; i < msg_bytes; i++)
      Y[i- j] ^= buff[i - j];
  }

  else if (msg_bytes - i > 0) /* C*, C** */ 
  {
    cipher(buff, S, -1, 3, context); 
    xor_block(&C[i], &M[i], buff); 
    cipher(buff, &C[i], 0, 3, context); 
    xor_block(Y, Y, buff); 

    i += 16; 
    cipher(buff, S, -1, 4, context); 
    for (j = i; i < msg_bytes; i++) 
      C[i] = M[i] ^ buff[i - j];
    
    zero_block(buff); 
    for (j = i; i < msg_bytes; i++) 
      buff[i - j] = C[i]; 
    buff[i - j] = 0x80; 
    cipher(buff, buff, 0, 4, context); 

    for (j = i; i < msg_bytes; i++)
      Y[i- j] ^= buff[i - j];
  }
  
  if (!inv) cipher(buff, R1, -1, 2, context); 
  else      cipher(buff, R1, -1, 1, context); 
  xor_block(&C[16], R0, buff); 

  if (!inv) cipher(C, &C[16], 0, 2, context);
  else      cipher(C, &C[16], 0, 1, context);
  xor_block(C, C, R1); 
  xor_block(C, C, delta); 
  xor_block(&C[16], &C[16], Y); 

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
    buff[i] = C[i]; 
  buff[0] |= 0x01; 
  xor_block(buff, buff, delta); 
  cipher(buff, buff, 0, 7, context); 
  C[0] ^= (buff[0] & 0x01);  
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

  ahash(delta, T, tag_bytes, context); 
  l = (msg_bytes + 1) / 2; 
  memcpy(C, M, msg_bytes);

  if (inv && msg_bytes < 16) 
    point_swap(C, delta, msg_bytes, context); 

  memcpy(front, C, l); 
  memcpy(back, &C[n], l); 

  if (msg_bytes & 1)
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
    cipher(buff, buff, 0, j, context); 
    xor_block(A, A, buff); 
    if (!inv) ++ctr;
    else      --ctr; 

    zero_block(buff); 
    memcpy(buff, A, l); 
    buff[n] = (buff[n] & mask) | pad; 
    xor_block(buff, buff, delta);
    buff[0] ^= ctr; 
    cipher(buff, buff, 0, j, context); 
    xor_block(B, B, buff); 
    if (!inv) ++ctr;
    else      --ctr; 
  }
    
  memcpy(buff, front, n);
  memcpy(&buff[n], back, l);
  if (msg_bytes & 1) 
  {
    for (i = msg_bytes - 1; i > n; i--)
       buff[i] = (Byte)((buff[i] >> 4) | (buff[i-1] << 4));
     buff[n] = (Byte)((back[0] >> 4) | (front[n] & mask));
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
      Byte *res = malloc(data_bytes+16);
      memset(res,0,16);
      res[0] = (Byte)(nonce_bytes == 12 ? auth_bytes | 0x40 : auth_bytes);
      memcpy(res+4, N, nonce_bytes);
      if (nonce_bytes < 12) res[nonce_bytes+4] = 0x80;
      memcpy(res+16, A, data_bytes);
      tag_bytes = data_bytes+16;
      *T = res;
  } else {
      unsigned pdata_bytes = 16 - (data_bytes % 16);
      Byte *res = malloc(5+nonce_bytes+data_bytes+pdata_bytes);
      res[0] = (Byte)(auth_bytes | 0x80);
      res[1] = res[2] = res[3] = 0;
      memcpy(res+4, N, 12);
      memcpy(res+16, A, data_bytes);
      res[16+data_bytes] = 0x80;
      memset(res+16+data_bytes+1,0,pdata_bytes-1);
      memcpy(res+16+data_bytes+pdata_bytes,N+12,nonce_bytes-12);
      res[4+nonce_bytes+data_bytes+pdata_bytes] = (Byte)nonce_bytes;
      tag_bytes = 5+nonce_bytes+data_bytes+pdata_bytes;
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
  
  if (msg_bytes == 0)
  {
    amac(X, T, tag_bytes, context); 
    memcpy(C, X, auth_bytes); 
  }

  else
  {
    memcpy(X, M, msg_bytes); 
    memset(X + msg_bytes, 0, auth_bytes);
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

//static void display_block(const Block X) 
//{
//  for (int i = 0; i < 4; i ++)
//    printf("0x%08x ", *(uint32_t *)&X[i * 4]); 
//}

//static void display_context(Context *context)
//{
//  unsigned i; 
//  printf("+---------------------------------------------------------+\n"); 
//  for (i = 0; i < 11; i++)
//  {
//    printf("| Klong[%-2d] = ", i); 
//    display_block(context->Klong[i]); 
//    printf("|\n"); 
//  }
//
//  printf("+---------------------------------------------------------+\n"); 
//  for (i = 0; i < 5; i++)
//  {
//    printf("| Kshort[%d] = ", i); 
//    display_block(context->Kshort[i]); 
//    printf("|\n"); 
//  }
//
//  printf("+---------------------------------------------------------+\n"); 
//  for (i = 0; i < 8; i++)
//  {
//    printf("| J[%-2d] =     ", i); 
//    display_block(context->J[i]); 
//    printf("|\n"); 
//  }
//
//  printf("+---------------------------------------------------------+\n"); 
//  printf("| L     =     "); 
//  display_block(context->L); 
//  printf("|\n"); 
//  
//  printf("| Linit =     "); 
//  display_block(context->Linit); 
//  printf("|\n"); 
//  printf("+---------------------------------------------------------+\n"); 
//}

#define HZ (2.9e9) 
#define TRIALS 1000000

void benchmark() {

  static const int msg_len [] = {64,     128,  256,   512, 
                                 1024,   4096, 10000, 100000,
                                 1000000}; 
  static const int num_msg_lens = 7; 
  unsigned i, j, auth_bytes = 16, key_bytes = 16; 
  
  Context context; 
  ALIGN(16) Block key   = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};  
  ALIGN(16) Block nonce = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};  
  init(&context, key, key_bytes);

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
      encrypt(ciphertext, message, nonce, NULL, 
                  msg_len[i], 16, 0, auth_bytes, &context); 
      ((unsigned long *)nonce)[0] ++; 
    }
    t = clock() - t; 
    total_cycles = t * HZ / CLOCKS_PER_SEC; 
    total_bytes = (double)TRIALS * msg_len[i]; 
    printf("%8d bytes, %.2f cycles per byte\n", msg_len[i], 
                               total_cycles/total_bytes); 
  }
  
  //ciphertext[343] = 'o';
  ((unsigned long *)nonce)[0] --; i --; 
  if (decrypt(plaintext, ciphertext, nonce, NULL, 
               msg_len[i] + auth_bytes, 16, 0, auth_bytes, &context) != INVALID)
    printf("Success! ");
  else 
    printf("Tag mismatch. ");
  printf("\n"); 

  free(message); 
  free(ciphertext); 
  free(plaintext); 
}



/* ------------------------------------------------------------------------- */ 
/* ------ Reference code START --------------------------------------------- */ 
/* ------------------------------------------------------------------------- */ 


typedef unsigned char byte;

/* Endian adjust 32-bit words on little-endian cpu's for rijndael-alg-fst    */
static void correct_key(byte *src, unsigned nbytes, byte *dst) {
    const union { int x; char e; } l = { 1 };
    if (l.e) {
        u32 i, *s = (u32 *)src, *d = (u32 *)dst;
        for (i=0; i<nbytes/4; i++)
            d[i] = ((s[i] & 0x000000ffu) << 24) | ((s[i] & 0x0000ff00u) <<  8)
                 | ((s[i] & 0x00ff0000u) >>  8) | ((s[i] & 0xff000000u) >> 24);
    }
}

/* ------------------------------------------------------------------------- */

static void xor_bytes(byte *src1, byte *src2, unsigned n, byte *dst) {
    while (n) { n--; dst[n] = src1[n] ^ src2[n]; }
}

/* ------------------------------------------------------------------------- */

static void rev(byte *src, byte *dst) {
    byte i, tmp[16];
    memcpy(tmp,src,16);
    for (i=0; i<16; i++) dst[i] = tmp[15-i];
}

/* ------------------------------------------------------------------------- */

static void double_block(byte *src, byte *dst) {
    byte i, tmp = src[0];
    for (i=0; i<15; i++)
        dst[i] = (byte)((src[i] << 1) | (src[i+1] >> 7));
    dst[15] = (byte)((src[15] << 1) ^ ((tmp >> 7) * 135));
}

/* ------------------------------------------------------------------------- */

static void mult_block(unsigned x, byte *src, byte *dst) {
    byte t[16], r[16];
    rev(src,t); memset(r,0,16);
    for ( ; x; x>>=1) {
        if (x&1) xor_bytes(r,t,16,r);
        double_block(t,t);
    }
    rev(r,dst);
}

/* ------------------------------------------------------------------------- */

/*
C1 C6FE23AF13A3A2043920BAE4DF66DE3F
C2 0FD2EFC0BB1517C1D6143E0DA501486F
C3 16F6310A1916DC27091D517219FBB171
C4 A0552CE664772F2C0AF8FEB11F0BCC75
C5 75604DC2DA7C95BB380BE04B07C87D55
C6 96E868DA0A419725297491FCF3FFC082
C7 E6E60579503649FBF4BE40E7B94D7B7B
*/
static void Extract(byte *K, unsigned kbytes, byte extracted_key[2*16]) {
    u32 aes4_key[4*5], aes4_key_a[4*5], aes4_key_b[4*5];
    byte i, buf[16], C[16], C3[16];
    byte key_constant[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    
    /* Setup key schedules and offsets */
    for (i=0; i<5; i++) memcpy((byte*)aes4_key+i*16,key_constant,16);
    correct_key((byte*)aes4_key, 5*16, (byte*)aes4_key);    
    memset(aes4_key_a,0,80); memset(aes4_key_b,0,80);      
    memset((byte*)aes4_key_a+16, 1, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_a+16, 4);
    memset((byte*)aes4_key_a+32, 2, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_a+32, 4);
    memset((byte*)aes4_key_a+48, 3, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_a+48, 4);
    memset((byte*)aes4_key_b+16, 4, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_b+16, 4);
    memset((byte*)aes4_key_b+32, 5, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_b+32, 4);
    memset((byte*)aes4_key_b+48, 6, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_b+48, 4);
    memset(C,7,16); rijndaelEncryptRound(aes4_key, 10, C, 4);
    correct_key((byte*)aes4_key_a+16, 3*16, (byte*)aes4_key_a+16);
    correct_key((byte*)aes4_key_b+16, 3*16, (byte*)aes4_key_b+16);
    mult_block(2,C,buf); xor_bytes(C,buf,16,C3);
    
    memset(extracted_key,0,32);
    for ( ; kbytes >= 16; kbytes-=16, K+=16) {
        xor_bytes(K, C, 16, buf);
        rijndaelEncryptRound(aes4_key_a, 10, buf, 4);
        xor_bytes(extracted_key, buf, 16, extracted_key);
        xor_bytes(K, C, 16, buf);
        rijndaelEncryptRound(aes4_key_b, 10, buf, 4);
        xor_bytes(extracted_key+16, buf, 16, extracted_key+16);
        mult_block(2,C,C);
    }
    if (kbytes) {
        memset(buf,0,16); memcpy(buf,K,kbytes); buf[kbytes]=0x80;
        xor_bytes(buf, C3, 16, buf);
        rijndaelEncryptRound(aes4_key_a, 10, buf, 4);
        xor_bytes(extracted_key, buf, 16, extracted_key);
        memset(buf,0,16); memcpy(buf,K,kbytes); buf[kbytes]=0x80;
        xor_bytes(buf, C3, 16, buf);
        rijndaelEncryptRound(aes4_key_b, 10, buf, 4);
        xor_bytes(extracted_key+16, buf, 16, extracted_key+16);
    }
}

/* ------------------------------------------------------------------------- */

static void Expand(byte extracted_key[2*16], byte expanded_key[6*16]) {
    u32 i, aes4_key[4*5];
    
    /* Setup round keys: Adjust and copy K0:K1, then replicate to others */
    memcpy((byte*)aes4_key+0, extracted_key, 32);            /* J:L to K0:K1 */
    mult_block(2, extracted_key, (byte*)aes4_key+32);        /* 2J to K2     */
    memcpy((byte*)aes4_key+48, extracted_key+16, 16);        /* L to K3      */
    mult_block(2, (byte*)aes4_key+32, (byte*)aes4_key+64);   /* 4J to K4     */
    correct_key((byte*)aes4_key,5*16,(byte*)aes4_key);
    
    /* Generate bytes */
    memcpy(expanded_key, extracted_key, 32);
    for (i=0; i<4; i++) {
        memset(expanded_key+i*16+32, (char)i, 16);
        rijndaelEncryptRound(aes4_key, 10, expanded_key+i*16+32, 4);
    }
}

/* ------------------------------------------------------------------------- */

static void E(byte *K, unsigned kbytes, int i, unsigned j,
                                                byte src[16], byte dst[16]) {
    byte extracted_key[2*16], expanded_key[6*16], J[16], L[16], buf[16];
    u32 aes_key[4*11];

    /* Build key schedule for AES. AES4 schedules are contained within */
    Extract(K, kbytes, extracted_key);
    Expand(extracted_key, expanded_key);
    memcpy(J, expanded_key, 16); memcpy(L, expanded_key+16, 16);
    memcpy((byte*)aes_key+0, L, 16);
    memcpy((byte*)aes_key+16, J, 16);
    mult_block(2,(byte*)aes_key+16,(byte*)aes_key+32);
    mult_block(2,(byte*)aes_key+32,(byte*)aes_key+48);
    memcpy((byte*)aes_key+64, expanded_key+32, 64);
    memcpy((byte*)aes_key+128, expanded_key+32, 48);
    correct_key((byte*)aes_key,11*16,(byte*)aes_key);
    
    /* Encipher */
    mult_block(j%8, J, buf); xor_bytes(buf, src, 16, buf);
    if (i < 0)
        rijndaelEncrypt(aes_key, 10, buf, dst);
    else {
        u32 aes4_key[4*5];
        memcpy((byte*)aes4_key, (byte*)aes_key+64+i*16, 64);
        memset((byte*)aes4_key+64, 0, 16);
        if ((i > 0) && (j > 0)) {
            for ( ; j > 8; j-=8) mult_block(2,L,L);  /* L = 2^((j-1)/8) L */
            xor_bytes(buf, L, 16, buf);
        }
        rijndaelEncryptRound(aes4_key, 10, buf, 4);
        memcpy(dst, buf, 16);
    }
}

/* ------------------------------------------------------------------------- */

static void AHash(byte *K, unsigned kbytes, byte *A,
                                            unsigned abytes, byte *result) {
    byte buf[16], sum[16];
    unsigned j;
    
    memset(sum,0,16);
    for (j=0; abytes >= 16; abytes -= 16, A += 16, j += 1) {
        E(K,kbytes,3,j,A,buf); xor_bytes(sum, buf, 16, sum);
    }
    if (abytes) {
        memset(buf,0,16); memcpy(buf,A,abytes); buf[abytes]=0x80;
        E(K,kbytes,1,0,buf,buf);
        xor_bytes(sum, buf, 16, result);
    } else
        memcpy(result, sum, 16);
}

/* ------------------------------------------------------------------------- */

static void AMac(byte *K, unsigned kbytes, byte *A,
                                            unsigned abytes, byte *result) {
    byte buf[16];
    AHash(K, kbytes, A, abytes, buf); 
    E(K,kbytes,-1,5,buf,result);
}

/* ------------------------------------------------------------------------- */

/* Set d=0 for EncipherEME4 and d=1 for DecipherEME4 */
static void CipherEME4(byte *K, unsigned kbytes, byte *T, unsigned tbytes,
                        byte *in, unsigned inbytes, unsigned d, byte *out) {
    byte tmp[16], Delta[16], X[16], Y[16], S[16];
    byte *in_orig = in, *out_orig = out;
    unsigned j, inbytes_orig = inbytes;
    
    memset(X,0,16); memset(Y,0,16);
    AHash(K, kbytes, T, tbytes, Delta);
    
    /* Pass 1 over in[32..], store intermediate values in out[32..] */
    inbytes = inbytes_orig - 32; out = out_orig + 32; in = in_orig + 32;
    for (j=1; inbytes >= 32; j++, inbytes-=32, in+=32, out+=32) {
        E(K, kbytes, 1, j, in+16, tmp); xor_bytes(in, tmp, 16, out);
        E(K, kbytes, 0, 0, out, tmp); xor_bytes(in+16, tmp, 16, out+16);
        xor_bytes(out+16, X, 16, X);
    }
    
    /* Finish X calculation */
    if (inbytes >= 16) {
        E(K, kbytes, 0, 3, in, tmp); xor_bytes(X, tmp, 16, X);
        inbytes -= 16; in += 16; out += 16;
        memset(tmp,0,16); memcpy(tmp,in,inbytes); tmp[inbytes] = 0x80;
        E(K, kbytes, 0, 4, tmp, tmp); xor_bytes(X, tmp, 16, X);
    } else if (inbytes > 0) {
        memset(tmp,0,16); memcpy(tmp,in,inbytes); tmp[inbytes] = 0x80;
        E(K, kbytes, 0, 3, tmp, tmp); xor_bytes(X, tmp, 16, X);
    }
    
    /* Calculate S */
    xor_bytes(Delta, in_orig, 16, out_orig);
    xor_bytes(X, in_orig+16, 16, out_orig+16);
    E(K, kbytes, 0, 1+d, out_orig+16, tmp);
    xor_bytes(out_orig, tmp, 16, out_orig);
    E(K, kbytes, -1, 1+d, out_orig, tmp);
    xor_bytes(out_orig+16, tmp, 16, out_orig+16);
    xor_bytes(out_orig, out_orig+16, 16, S);
    
    /* Pass 2 over intermediate values in out[32..]. Final values written */
    inbytes = inbytes_orig - 32; out = out_orig + 32; in = in_orig + 32;
    for (j=1; inbytes >= 32; j++, inbytes-=32, in+=32, out+=32) {
        E(K, kbytes, 2, j, S, tmp);
        xor_bytes(out, tmp, 16, out); xor_bytes(out+16, tmp, 16, out+16);
        xor_bytes(out, Y, 16, Y);
        E(K, kbytes, 0, 0, out+16, tmp); xor_bytes(out, tmp, 16, out);
        E(K, kbytes, 1, j, out, tmp); xor_bytes(out+16, tmp, 16, out+16);
        memcpy(tmp, out, 16); memcpy(out, out+16, 16); memcpy(out+16, tmp, 16);
    }

    /* Finish Y calculation and finish encryption of tail bytes */
    if (inbytes >= 16) {
        E(K, kbytes, -1, 3, S, tmp); xor_bytes(in, tmp, 16, out);
        E(K, kbytes, 0, 3, out, tmp); xor_bytes(Y, tmp, 16, Y);
        inbytes -= 16; in += 16; out += 16;
        E(K, kbytes, -1, 4, S, tmp); xor_bytes(in, tmp, inbytes, tmp);
        memcpy(out,tmp,inbytes);
        memset(tmp+inbytes,0,16-inbytes); tmp[inbytes] = 0x80;
        E(K, kbytes, 0, 4, tmp, tmp); xor_bytes(Y, tmp, 16, Y);
    } else if (inbytes > 0) {
        E(K, kbytes, -1, 3, S, tmp); xor_bytes(in, tmp, inbytes, tmp);
        memcpy(out,tmp,inbytes);
        memset(tmp+inbytes,0,16-inbytes); tmp[inbytes] = 0x80;
        E(K, kbytes, 0, 3, tmp, tmp); xor_bytes(Y, tmp, 16, Y);
    }
    
    /* Finish encryption of first two blocks */
    E(K, kbytes, -1, 2-d, out_orig+16, tmp);
    xor_bytes(out_orig, tmp, 16, out_orig);
    E(K, kbytes, 0, 2-d, out_orig, tmp);
    xor_bytes(out_orig+16, tmp, 16, out_orig+16);
    xor_bytes(Y, out_orig, 16, out_orig);
    xor_bytes(Delta, out_orig+16, 16, out_orig+16);
    memcpy(tmp, out_orig, 16);
    memcpy(out_orig, out_orig+16, 16);
    memcpy(out_orig+16, tmp, 16);
}

/* ------------------------------------------------------------------------- */

/* Set d=0 for EncipherFF0 and d=1 for DecipherFF0 */
static void CipherFF0(byte *K, unsigned kbytes, byte *T, unsigned tbytes,
                        byte *in, unsigned inbytes, unsigned d, byte *out) {
    unsigned rounds,i,j=6,k;
    int step;
    byte mask=0x00, pad=0x80, Delta[16], L[16], R[16], buf[32];
    AHash(K, kbytes, T, tbytes, Delta);
    if      (inbytes==1) rounds=24;
    else if (inbytes==2) rounds=16;
    else if (inbytes<16) rounds=10;
    else {          j=5; rounds=8; }
    /* Split (inbytes*8)/2 bits into L and R. Beware: May end in nibble. */
    memcpy(L, in,           (inbytes+1)/2);
    memcpy(R, in+inbytes/2, (inbytes+1)/2);
    if (inbytes&1) {                     /* Must shift R left by half a byte */
        for (i=0; i<inbytes/2; i++)
            R[i] = (byte)((R[i] << 4) | (R[i+1] >> 4));
        R[inbytes/2] = (byte)(R[inbytes/2] << 4);
        pad = 0x08; mask = 0xf0;
    }
    if (d) {
        if (inbytes < 16) {
            memset(buf,0,16); memcpy(buf,in,inbytes); buf[0] |= 0x80;
            xor_bytes(Delta, buf, 16, buf);
            E(K, kbytes,0,7,buf,buf);
            L[0] ^= (buf[0] & 0x80);
        }
        i = rounds-1; step = -1;
    } else {
        i = 0; step = 1;
    }
    for (k=0; k<rounds/2; k++,i=(unsigned)((int)i+2*step)) {
        memset(buf, 0, 16);
        memcpy(buf,R,(inbytes+1)/2);
        buf[inbytes/2] = (buf[inbytes/2] & mask) | pad;
        xor_bytes(buf, Delta, 16, buf);
        buf[15] ^= (byte)i;
        E(K, kbytes,0,j,buf,buf);
        xor_bytes(L, buf, 16, L);

        memset(buf, 0, 16);
        memcpy(buf,L,(inbytes+1)/2);
        buf[inbytes/2] = (buf[inbytes/2] & mask) | pad;
        xor_bytes(buf, Delta, 16, buf);
        buf[15] ^= (byte)((int)i+step);
        E(K, kbytes,0,j,buf,buf);
        xor_bytes(R, buf, 16, R);
    }
    memcpy(buf,           R, inbytes/2);
    memcpy(buf+inbytes/2, L, (inbytes+1)/2);
    if (inbytes&1) {
        for (i=inbytes-1; i>inbytes/2; i--)
            buf[i] = (byte)((buf[i] >> 4) | (buf[i-1] << 4));
        buf[inbytes/2] = (byte)((L[0] >> 4) | (R[inbytes/2] & 0xf0));
    }
    memcpy(out,buf,inbytes);
    if ((inbytes < 16) && !d) {
        memset(buf+inbytes,0,16-inbytes); buf[0] |= 0x80;
        xor_bytes(Delta, buf, 16, buf);
        E(K, kbytes,0,7,buf,buf);
        out[0] ^= (buf[0] & 0x80);
    }
}

/* ------------------------------------------------------------------------- */

static void Encipher(byte *K, unsigned kbytes, byte *T, unsigned tbytes,
                                    byte *in, unsigned inbytes, byte *out) {
    if (inbytes == 0) return;
    if (inbytes < 32) CipherFF0(K, kbytes, T, tbytes, in, inbytes, 0, out);
    else              CipherEME4(K, kbytes, T, tbytes, in, inbytes, 0, out);
}

/* ------------------------------------------------------------------------- */

static void Decipher(byte *K, unsigned kbytes, byte *T, unsigned tbytes,
                                    byte *in, unsigned inbytes, byte *out) {
    if (inbytes == 0) return;
    if (inbytes < 32) CipherFF0(K, kbytes, T, tbytes, in, inbytes, 1, out);
    else              CipherEME4(K, kbytes, T, tbytes, in, inbytes, 1, out);
}

/* ------------------------------------------------------------------------- */

static void Format(byte *N, unsigned nbytes, byte *AD, unsigned adbytes,
                                unsigned abytes, byte **T, unsigned *tbytes) {
    if (nbytes <= 12) {
        byte *res = (byte *)malloc(adbytes+16);
        memset(res,0,16);
        res[0] = (byte)(nbytes == 12 ? abytes | 0x40 : abytes);
        memcpy(res+4, N, nbytes);
        if (nbytes < 12) res[nbytes+4] = 0x80;
        memcpy(res+16, AD, adbytes);
        *tbytes = adbytes+16;
        *T = res;
    } else {
        unsigned padbytes = 16 - (adbytes % 16);
        byte *res = (byte *)malloc(12+nbytes+adbytes+padbytes);
        res[0] = (byte)(abytes | 0x80);
        res[1] = res[2] = res[3] = 0;
        memcpy(res+4, N, 12);
        memcpy(res+16, AD, adbytes);
        res[16+adbytes] = 0x80;
        memset(res+16+adbytes+1,0,padbytes-1);
        memcpy(res+16+adbytes+padbytes,N+12,nbytes-12);
        memset(res+4+nbytes+adbytes+padbytes, 0, 4);
        res[8+nbytes+adbytes+padbytes] = (byte)(nbytes >> 24);
        res[9+nbytes+adbytes+padbytes] = (byte)(nbytes >> 16);
        res[10+nbytes+adbytes+padbytes] = (byte)(nbytes >> 8);
        res[11+nbytes+adbytes+padbytes] = (byte)nbytes;
        *tbytes = 12+nbytes+adbytes+padbytes;
        *T = res;
    }
}

/* ------------------------------------------------------------------------- */

int Decrypt(byte *K, unsigned kbytes, byte *N, unsigned nbytes,
            byte *AD, unsigned adbytes, byte *C, unsigned cbytes,
            unsigned abytes, byte *M) {
    byte *T, *X, sum=0;
    unsigned tbytes,i;
    if (cbytes < abytes) return -1;
    Format(N, nbytes, AD, adbytes, abytes, &T, &tbytes);
    if (cbytes==abytes) {
        byte buf[16];
        AMac(K, kbytes, T, tbytes, buf);
        for (i=0; i<abytes; i++) sum |= (buf[i] ^ C[i]);
    } else {
        X = (byte *)malloc(cbytes);
        Decipher(K, kbytes, T, tbytes, C, cbytes, X);
        for (i=0; i<abytes; i++) sum |= X[cbytes-abytes+i];
        if (sum==0) memcpy(M,X,cbytes-abytes);
        free(X);
    }
    free(T);
    return (sum == 0 ? 0 : -1);  /* return 0 if valid, -1 if invalid */
}

/* ------------------------------------------------------------------------- */

void Encrypt(byte *K, unsigned kbytes, byte *N, unsigned nbytes,
             byte *AD, unsigned adbytes, byte *M, unsigned mbytes,
             unsigned abytes, byte *C) {
    byte buf[16], *T, *X;
    unsigned tbytes;
    Format(N, nbytes, AD, adbytes, abytes, &T, &tbytes);
    if (mbytes==0) {
        AMac(K, kbytes, T, tbytes, buf);
        memcpy(C,buf,abytes);
    } else {
        X = (byte *)malloc(mbytes+abytes);
        memcpy(X, M, mbytes); memset(X+mbytes,0,abytes);
        Encipher(K, kbytes, T, tbytes, X, mbytes+abytes, X);
        memcpy(C, X, mbytes+abytes);
        free(X);
    }
    free(T);
}

/* ------------------------------------------------------------------------- */ 
/* ------ Reference code END ----------------------------------------------- */ 
/* ------------------------------------------------------------------------- */ 


int main()
{
  //benchmark(); 

  Context context; 
  Block key   = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};  
  Block nonce = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};  
  unsigned key_bytes = 16, nonce_bytes = 16; 
  
  Byte message [] = "0000000000000000000000000000000000000000000",
       ciphertext[256], 
       plaintext[256]; 

  unsigned msg_bytes = strlen((const char *)message), 
           auth_bytes = 16, i; 

 
  
  Encrypt(key, key_bytes, nonce, nonce_bytes, NULL, 0, 
      message, msg_bytes, auth_bytes, ciphertext); 
                         
  for (i = 0; i < msg_bytes + auth_bytes; i++)
    printf("%02x", ciphertext[i]); 
  printf("\n"); 

  init(&context, key, key_bytes);
  encrypt(ciphertext, message, nonce, NULL, 
             msg_bytes, nonce_bytes, 0, auth_bytes, &context); 
  
  for (i = 0; i < msg_bytes + auth_bytes; i++)
    printf("%02x", ciphertext[i]); 
  printf("\n"); 

  int res = decrypt(plaintext, ciphertext, nonce, NULL, 
              msg_bytes + auth_bytes, nonce_bytes, 0, auth_bytes, &context); 

  if (res == INVALID) printf("Reject!"); 
  else 
  {
    for (i = 0; i < msg_bytes; i++) 
      printf("%c", plaintext[i]); 
  }
  printf("\n"); 


  return 0; 
}
