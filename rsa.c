/**
 * rsa.c - Implementation of textbook RSA. 
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

#include "rsa.h"
#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#define BUFFER_LENGTH 4096
#define KEY_OUTPUT_BASE 32

/* 
 * Funciton prime
 * 
 * Description
 *   Generate an n-bit integer congruent to 2 (mod 3) which passes the 
 *   Miller-Rabin primality test (100 trials). Run until success.  
 */
void prime(mpz_t p, gmp_randstate_t state, int n) 
{ 

  while (1)
  {
    /* Random odd integer. */  
    mpz_urandomb(p, state, n); 
    mpz_setbit(p, 0);

    /* Ensure that p = 2 (mod 3). */ 
    switch (mpz_fdiv_ui(p, 3)) 
    {
      case 0: // not prime. 
        continue; 
      case 1: mpz_sub_ui(p, p, 2); 
    }

    /* Miller-Rabin primality test. */ 
    switch (mpz_probab_prime_p(p, 100))
    {
      case 0: // not prime.
        continue;  
      case 1: // probably prime. 
      case 2: // definitely prime. 
        return; 
    }
  }
}

/* 
 * Function gen_rsa
 * 
 * Description
 *   Generate RSA paramters given `n` and a GMP random `state`. 
 *
 * Return 
 *   1 if success, 0 if failure. (This won't happen if `e`=3. 
 */
int rsa_gen(rsa_private_t *secret_key, rsa_public_t *public_key, gmp_randstate_t state, int n)
{
  int res = 1; 
  mpz_t gcd, x, y, p, q, phi, N; 
  mpz_inits( gcd, x, y, p, q, phi, N, NULL ); 

  /* Generate random n-bit primes p and q, such that p = q = 2 (mod 3). 
   * Since e = 3 in this impelmentation, this ensures that gcd(e, phi(N)) = 1,
   * the basic correctness requirement. */ 
  prime( p, state, n );
  prime( q, state, n );  
  //mpz_set_ui(p, 7499);
  //mpz_set_ui(q, 7517);
  mpz_mul( N, p, q );  
  
  /* Message length in bits. */ 
  secret_key->n = public_key->n = mpz_sizeinbase( N, 2 ); 
  
  /* Initialize public key. */ 
  mpz_init_set_ui (public_key->e, 3 ); 
  mpz_init_set( public_key->N, N ); 

  /* Initialize private key. */ 
  mpz_inits( secret_key->d, 
             secret_key->id_p, secret_key->id_q, 
             secret_key->t_p, secret_key->t_q, 
             secret_key->m_p, secret_key->m_q, NULL ); 
  mpz_init_set( secret_key->N, N ); 
  mpz_init_set( secret_key->p, p ); 
  mpz_init_set( secret_key->q, q ); 
  
  /* Compute corresponding values in Zpq of identities in (Zp X Zq). */ 
  mpz_gcdext( gcd, x, y, p, q ); 
  mpz_mul( y, y, q ); 
  mpz_mul( x, x, p ); 
  mpz_mod( secret_key->id_p, y, N ); // id_p = yq mod N
  mpz_mod( secret_key->id_q, x, N ); // id_q = xp mod N

  /* Compute d = e^-1 (mod phi(N)). */
  mpz_sub_ui( p, p, 1 ); 
  mpz_sub_ui( q, q, 1 ); 
  mpz_mul( phi, p, q ); // phi(N) = (p-1)(q-1)
  mpz_gcdext( gcd, secret_key->d, y, public_key->e, phi );
  mpz_mod( secret_key->d, secret_key->d, phi ); // d = e^-1 mod phi(N)
  if (mpz_cmp_ui( gcd, 1 ) != 0) 
    res = 0; 
 
  mpz_mod(secret_key->t_p, secret_key->d, p); // d mod (p-1)
  mpz_mod(secret_key->t_q, secret_key->d, q); // d mod (q-1)

  mpz_clears( gcd, x, y, p, q, phi, N, NULL ); 

  return res; 
}


/*
 * Function rsa_enc
 *
 * Description
 *   Textbook (i.e. insecure) RSA encryption. `N` is the public key, and `e` 
 *   is a parameter of the algorihtm. `e` = 3 in this implementation. This is 
 *   small to make encryption efficient. 
 */
void rsa_enc(mpz_t ciphertext, const mpz_t plaintext, rsa_public_t *public_key)
{
  mpz_powm(ciphertext, plaintext, public_key->e, public_key->N); // FIXME timing mpz_pown_sec 
}

/* 
 * Function rsa_dec
 * 
 * Description
 *   Textbook (i.e. insecure) RSA decryption. The full set of RSA parameters 
 *   contains the secret `d`, as well as the factorization of `N`, to make 
 *   decryption more efficient via the Chinese remainder theorem. 
 */
void rsa_dec(mpz_t plaintext, const mpz_t ciphertext, rsa_private_t *secret_key)
{
  mpz_powm(secret_key->m_p, ciphertext, secret_key->t_p, secret_key->p); // FIXME timing mpz_pown_sec
  mpz_mul(secret_key->m_p, secret_key->m_p, secret_key->id_p); 
  
  mpz_powm(secret_key->m_q, ciphertext, secret_key->t_q, secret_key->q); // FIXME timing mpz_powm_sec
  mpz_mul(secret_key->m_q, secret_key->m_q, secret_key->id_q);

  mpz_add(plaintext, secret_key->m_p, secret_key->m_q); 
  mpz_mod(plaintext, plaintext, secret_key->N); 
}

/*
 * Function rsa_read_private
 *
 * Description
 *   Read key from file and initialize private key structure. 
 *   FIXME Need to do format check. 
 */
int rsa_read_private(rsa_private_t *secret_key, const char *fn) 
{
  FILE *fd = fopen(fn, "r"); 
  if (!fd) 
    return 0; 
  char *buff = malloc(BUFFER_LENGTH * sizeof(char)); 
  mpz_t gcd, x, y, p, q, N; 
  mpz_inits( gcd, x, y, p, q, N, NULL );
  
  readline(buff, fd, BUFFER_LENGTH, ':'); 
  secret_key->n = atoi(buff);
  readline(buff, fd, BUFFER_LENGTH, ':'); 
  mpz_init_set_str(secret_key->d, buff, KEY_OUTPUT_BASE); 
  readline(buff, fd, BUFFER_LENGTH, ':'); 
  mpz_set_str(p, buff, KEY_OUTPUT_BASE); 
  readline(buff, fd, BUFFER_LENGTH, '\n'); 
  mpz_set_str(q, buff, KEY_OUTPUT_BASE); 
  
  /* Store p, q, and N = pq. */ 
  mpz_mul( N, p, q );  
  mpz_init_set(secret_key->N, N); 
  mpz_init_set(secret_key->p, p); 
  mpz_init_set(secret_key->q, q); 
  
  /* Compute corresponding values in Zpq of identities in (Zp X Zq). */ 
  mpz_inits( secret_key->id_p, secret_key->id_q, NULL );
  mpz_gcdext( gcd, x, y, p, q ); 
  mpz_mul( y, y, q ); 
  mpz_mul( x, x, p ); 
  mpz_mod( secret_key->id_p, y, N ); // id_p = yq mod N
  mpz_mod( secret_key->id_q, x, N ); // id_q = xp mod N

  /* Intermediate expnents in (Zp X Zq). */ 
  mpz_inits(secret_key->t_p, secret_key->t_q, NULL); 
  mpz_sub_ui( p, p, 1 ); 
  mpz_sub_ui( q, q, 1 ); 
  mpz_mod(secret_key->t_p, secret_key->d, p); // d mod (p-1)
  mpz_mod(secret_key->t_q, secret_key->d, q); // d mod (q-1)
  
  /* Book keeping */ 
  mpz_inits(secret_key->m_p, secret_key->m_q, NULL); 

  mpz_clears( gcd, x, y, p, q, N, NULL ); 
  
  free(buff); 
  fclose(fd); 
  return 1; 
}

/*
 * Funciton rsa_read_public
 * 
 * Description
 *   Read key from file and initialize public key structure. 
 *   FIXME Need to do format check. 
 */
int rsa_read_public(rsa_public_t *public_key, const char *fn) 
{
  FILE *fd = fopen(fn, "r"); 
  if (!fd) 
    return 0; 
  char *buff = malloc(BUFFER_LENGTH * sizeof(char)); 
  
  readline(buff, fd, BUFFER_LENGTH, ':'); 
  public_key->n = atoi(buff);
  readline(buff, fd, BUFFER_LENGTH, ':'); 
  mpz_init_set_str(public_key->e, buff, KEY_OUTPUT_BASE); 
  readline(buff, fd, BUFFER_LENGTH, '\n'); 
  mpz_init_set_str(public_key->N, buff, KEY_OUTPUT_BASE); 
  
  free(buff); 
  fclose(fd); 
  return 1; 
}

/* 
 * Function rsa_write_private 
 *
 * Description
 *   Store modulus length in bits, `d`, `p`, and `q`. 
 *
 * Return 1 if success, 0 if failure. 
 */
int rsa_write_private(rsa_private_t *secret_key, const char *fn)  
{
  FILE *fd = fopen(fn, "w"); 
  if (!fd) 
    return 0; 
  char *buff = malloc(BUFFER_LENGTH * sizeof(char)); 
  fprintf(fd, "%d:", secret_key->n); 
  fprintf(fd, "%s:", mpz_get_str(buff, KEY_OUTPUT_BASE, secret_key->d)); 
  fprintf(fd, "%s:", mpz_get_str(buff, KEY_OUTPUT_BASE, secret_key->p)); 
  fprintf(fd, "%s\n", mpz_get_str(buff, KEY_OUTPUT_BASE, secret_key->q)); 
  free(buff); 
  fclose(fd); 
  return 1; 
}

/* 
 * Function rsa_write_public
 *
 * Description
 *   Store modulus length in bits, `e`, and `N`.
 *
 * Return 1 if success, 0 if failure. 
 */
int rsa_write_public(rsa_public_t *public_key, const char *fn) 
{
  FILE *fd = fopen(fn, "w"); 
  if (!fd) 
    return 0;
  char *buff = malloc(BUFFER_LENGTH * sizeof(char)); 
  fprintf(fd, "%d:", public_key->n); 
  fprintf(fd, "%s:", mpz_get_str(buff, KEY_OUTPUT_BASE, public_key->e)); 
  fprintf(fd, "%s\n", mpz_get_str(buff, KEY_OUTPUT_BASE, public_key->N)); 
  free(buff); 
  fclose(fd); 
  return 1; 
}

/* 
 * Function rsa_free_private
 *
 * Description 
 *   Destroy private key structure. 
 */
void rsa_free_private(rsa_private_t *secret_key)
{
  mpz_clears( secret_key->N, 
              secret_key->d, 
              secret_key->p, secret_key->q, 
              secret_key->id_p, secret_key->id_q,
              secret_key->t_p, secret_key->t_q, 
              secret_key->m_p, secret_key->m_q, NULL ); 
}

/* 
 * Function rsa_free_public
 *
 * Description 
 *   Destroy public key structure. 
 */
void rsa_free_public(rsa_public_t *public_key)
{
  mpz_clears( public_key->N, 
              public_key->e, NULL ); 
}
