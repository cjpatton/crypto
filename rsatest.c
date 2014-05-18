/**
 * Testing, testing ... 
 *
 * NOTEs
 *  - modulo (%) is undefined for negative operands. (This is real stupid.) 
 *  - If m is not coprime to N, encryption still works. 
 *  - p and q must be prime for this to work mathematically.
 *  - paramaterize e such that d is relatively small ... this reduces the
 *    cost of encrypting / decrypting.
 *
 *  - Benchmarking for various values of BITS: 
 *     n     bytes  plaintexts time      KB/sec 
 *     128   16     1600000     
 *     256   32     1600000     :41   1216.5 
 *     512   64     40000   
 *     1024  128    20000         (redo. I know bandwidth decreases quickly.)
 *     2048  256    10000    
 *     4096  512    5000      
 *     8192 *didn't finish gen_rsa()
 */ 

#include "rsa.h"
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define BITS 512

int main(int argc, const char **argv)
{
  
  char buff[4096];

  gmp_randstate_t state; 
  gmp_randinit_default(state); 
  
  mpz_t m, c, a; 
  mpz_inits(m, c, a, NULL); 

  rsa_private_t sk;
  rsa_public_t pk; 
  
  if (argc == 2)
    gmp_randseed_ui(state, atoi(argv[1])); 
  else gmp_randseed_ui(state, 0); 
  
  int fella = 1; 
  if (fella)
  {
    printf("Generating RSA parameters ...\n"); 
    rsa_gen(&sk, &pk, state, BITS); 
    rsa_write_private(&sk, "fella");
    rsa_write_public(&pk, "fella.pub"); 
  }
  else
  {
    printf("Reading RSA parameters ...\n"); 
    rsa_read_private(&sk, "fella");
    rsa_read_public(&pk, "fella.pub"); 
  }
  //printf("public key:\n"); 
  //printf("N    = %s\n", mpz_get_str(buff, 10, pk.N)); 
  //printf("e    = %s\n\n", mpz_get_str(buff, 10, pk.e)); 
  
  //printf("secret key:\n"); 
  //printf("N    = %s\n", mpz_get_str(buff, 10, sk.N)); 
  //printf("d    = %s\n", mpz_get_str(buff, 10, sk.d)); 
  //printf("p    = %s\n", mpz_get_str(buff, 10, sk.p)); 
  //printf("q    = %s\n", mpz_get_str(buff, 10, sk.q)); 
  //printf("id_p = %s\n", mpz_get_str(buff, 10, sk.id_p)); 
  //printf("id_q = %s\n", mpz_get_str(buff, 10, sk.id_q)); 

  mpz_urandomb(m, state, BITS);  
  //mpz_set_str(m, "12334324342343234234234234234324324324234324283758579832759871", 10); 
  
  int i = 0, ct = 0, total = 10 * 16; 
  printf("Testing a bunch (%d) of plaintexts ... \n", total); 
  for (i = 0; i < total; i++)
  {
    rsa_enc(c, m, &pk); 
    rsa_dec(a, c, &sk); 
    if (mpz_cmp(a, m) != 0) 
    {
      printf("%-6d plaintext:  %s\n", i,mpz_get_str(buff, 10, m));
      printf("       ciphertext: %s\n", mpz_get_str(buff, 10, c));
      printf("       verify:     %s\n", mpz_get_str(buff, 10, a));
      ct ++; 
    }
    mpz_urandomb(m, state, BITS);  
  }
  if (ct == 0) 
    printf("No problem!\n"); 
  else 
    printf("There were %d fuck ups.\n", ct); 

  mpz_clears(m, c, a, NULL); 
  gmp_randclear(state); 
  
  rsa_free_private(&sk); 
  rsa_free_public(&pk); 
  
  return 0; 
}
