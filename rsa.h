/**
 * rsa.h - Header file for textbook RSA.  
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

#ifndef RSA_H
#define RSA_H

#include <stdint.h>
#include <gmp.h>

typedef struct {
  
  int n; /* Size of modulus N in bits. (Also the message length.) */ 

  /* Private key for RSA. (d is a secret.) */ 
  mpz_t d, N;    

  /* Factorization of N. (Definitely a secret.) */  
  mpz_t p, q;

  /* Values in Zpq corresponding to identities in (Zp X Zq). Used 
   * for efficient decryption via the Chinese Remainder Theorem. */
  mpz_t id_p, id_q; 

  /* Precomputed d mod (p-1), d mod (q-1) resp. (Secret.) */
  mpz_t t_p, t_q;  

  mpz_t m_p, m_q; /* Decryption book keeping. */ 

} rsa_private_t; 


typedef struct {
  
  int n; /* Size of modulus N in bits. (Also the message length.) */ 

  mpz_t e, N; /* Public key for RSA. */ 

} rsa_public_t; 


/* Randomly generate a v-bit integer passing the Miller-Rabin 
 * primality test. */
void prime(mpz_t p, gmp_randstate_t state, int n); 

/* Given two v-bit prime numbers, generate an RSA style
 * trapdoor permutation. */ 
int rsa_gen(rsa_private_t *secret_key, rsa_public_t *public_key, gmp_randstate_t state, int n); 

/* Textbook (i.e. insecure) RSA encryption. */
void rsa_enc(mpz_t ciphertext, const mpz_t plaintext, rsa_public_t *public_key); 

/* Textbook (i.e. insecure) RSA decryption. */
void rsa_dec(mpz_t plaintext, const mpz_t ciphertext, rsa_private_t *secret_key); 

/* Read keys from file. */ 
int rsa_read_private(rsa_private_t *secret_key, const char *fn);  
int rsa_read_public(rsa_public_t *public_key, const char *fn);  

/* Write out keys to file. */ 
int rsa_write_private(rsa_private_t *secret_key, const char *fn);  
int rsa_write_public(rsa_public_t *public_key, const char *fn);  

/* Destroy key structures. */ 
void rsa_free_private(rsa_private_t *secret_key); 
void rsa_free_public(rsa_public_t *public_key); 

#endif // RSA_H
