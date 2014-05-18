/**
 * oaep.h - Header for OAEP-RSA implementation (rfc3447).
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

#ifndef OAEP_H
#define OAEP_H

#include "rsa.h"
#include "sha1.h"
#include <stdio.h>

#define OAEP_BUFF_LENGTH 1 + (sizeof(unsigned long) * 8)
#define OAEP_MAX_HASH_LENGTH 64

/* 
 * Struct oaep_context_t
 *
 * Description
 *   Parameters and string buffers for OAEP-mode encryption operations. 
 *   (Note that a context should be instantiated for each thread.)   
 */
typedef struct Context
{
  /* A cryptographic hash function. */ 
  const uint8_t *(*H)(const uint8_t*, int, struct Context*); 

  /* Length (in bytes) of the encoding seed. This is also the 
   * width of the hash function `H`. */ 
  size_t lSeed; 

  /* Length (in bytes) of the RSA key's modulus N (and therefore the 
   * size of messages that can be encrypted). */ 
  size_t lN; 

  uint8_t hash [OAEP_MAX_HASH_LENGTH], 
          buff [OAEP_BUFF_LENGTH];
  
  /* Parameter for the SHA1 function. */ 
  SHA1Context sha; 
} oaep_context_t; 


/*
 * Enumerated type oaep_err_t, return value for padding, encoding, 
 * and encrypting routines. 
 */
typedef enum {
  oaepSuccess = 0,  
  oaepMsgLength,
  oaepCipherLength,
  oaepLabelMismatch,
  oaepModulusTooSmall
} oaep_err_t; 


  /*
   * High level functions
   */

int oaep_encrypt(char *ciphertext, const char *plaintext, size_t *lCipher, 
                 size_t lMsg, unsigned long label, rsa_public_t *public_key); 

int oaep_decrypt(char *plaintext, const char *ciphertext, size_t *lMsg, 
                 size_t lCipher, unsigned long label, rsa_private_t *secret_key); 

int oaep_encrypt_stream(FILE *fd_out, FILE *fd_in, unsigned long label, 
                        rsa_public_t *public_key); 

int oaep_decrypt_stream(FILE *fd_out, FILE *fd_in, unsigned long label, 
                        rsa_private_t *secret_key); 

#endif // OAEP_H
