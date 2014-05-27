/**
 * chacha.c - Implementation of the ChaCha stream cipher invented by 
 * Daniel Bernstein. (http://cr.yp.to/chacha.html)
 *
 * Copyright (C) 2014, Christopher Patton <chrispatton@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "chacha.h"
#include "../misc/portable.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* TODO Use portable primitives. */ 
#define QR(a, b, c, d) \
  a += b; d ^= a; d = (d << 16) | (d >> 16); \
  c += d; b ^= c; b = (b << 12) | (b >> 20); \
  a += b; d ^= a; d = (d << 8)  | (d >> 24); \
  c += d; b ^= c; b = (b << 7)  | (b >> 25); 

/*
 * Show ChaCha matrix. 
 */
void chacha_disp_state(const uint32_t X[16])
{
  int i;
  for (i = 0; i < 16; i++) 
  {
    printf("0x%08X ", u32_LITTLE(X[i])); 
    if ((i+1) % 4 == 0) printf("\n"); 
  }
}

/*
 * Initialize ChaCha state with `key`, nonce `n`, and block number `l`. 
 * Byte order of the key should be little endian. (This is guarenteed by 
 * key handling routines defined in `keygen.h`.) 
 */
void chacha_setup(uint32_t X[16],  
                  const uint32_t key[8], 
                  uint64_t n, uint64_t l)
{
  /* Key */
  memcpy(&X[4], key, 8 * sizeof(uint32_t)); 

  /* Constant. (These are just random integers. Bernstein 
   * recommends a particular set of constants.) */        
  X[0] = u32_LITTLE(1145093211);
  X[1] = u32_LITTLE(1566258456);
  X[2] = u32_LITTLE(440612657);
  X[3] = u32_LITTLE(1721837295);
  
  /* Initialization vector. */ 
  X[12] = u32_LITTLE((int32_t)n);
  X[13] = u32_LITTLE((int32_t)l);
  n >>= 32; l >>= 32; 
  X[14] = u32_LITTLE((int32_t)n);
  X[15] = u32_LITTLE((int32_t)l);
}

/*
 * 16-round ChaCha. 
 */
void chacha16(uint32_t X[16], const uint32_t input[16])
{
  int i;

  for (i = 0; i < CHA_BLOCK_u32; i++)
    X[i] = input[i];

  for (i = 0; i < 8; i++) 
  {
    /* Permute columns */ 
    QR(X[0], X[4], X[8],  X[12]);
    QR(X[1], X[5], X[9],  X[13]);
    QR(X[2], X[6], X[10], X[14]);
    QR(X[3], X[7], X[11], X[15]);
    
    /* Permute diagonals */ 
    QR(X[0], X[5], X[10], X[15]);
    QR(X[1], X[6], X[11], X[12]);
    QR(X[2], X[7], X[8],  X[13]);
    QR(X[3], X[4], X[9],  X[14]);
  }

  for (i = 0; i < CHA_BLOCK_u32; i++)
    X[i] ^= input[i]; 
}

/*
 * A blockcipher based on ChaCha. In order to use this cipher
 * securely, each block of an encrypted stream over a channel 
 * must have a unique nonce `n` and block number `l` pair. 
 */
void chacha_blockcipher(char *out, const char *in, 
                        const uint32_t key[8], 
                        uint64_t n, uint64_t l) 
{
  uint32_t i, *p=(uint32_t *)out, *q=(uint32_t *)in, X[16];
 
  memset(out, 0, CHA_BLOCK_u8 * sizeof(char)); 
  
  chacha_setup(X, key, n, l);
  //printf("Before\n");
  //chacha_disp_state(X); 

  chacha16(p, X); 
  //printf("After\n");
  //chacha_disp_state(p); 
  //printf("\n"); 

  for (i = 0; i < CHA_BLOCK_u32; i++)
  {
    *p ^= *q;
    p++; q++; 
  }
}

/*
 * A streamcipher based on ChaCha, valid up to 2^70 bytes. 
 * Output buffer `out` should be a multiple of the block size
 * `CHA_BLOCK_u8`. 
 */
void chacha_streamcipher(char *out, const char *in, size_t bytes, 
                         const uint32_t key[8], 
                         uint64_t n, uint64_t l)
{
  // TODO 
}
