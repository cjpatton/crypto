/**
 * oaep-rsa.c - Generate RSA keys, encrypt and decrypt files. 
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

#include "asym/oaep.h"
#include "asym/rsa.h"
#include "hash/sha1.h"
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NUMERIC(x) (x >= '0') && (x <= '9') 
#define ALPHABETIC(x) ((x >= 'a') && (x <= 'z')) || ((x >= 'A') && (x <= 'Z'))
#define MAX_FN 128

typedef struct {

  int n_bits, 
      encrypt,
      decrypt; 

  char fn_key [MAX_FN], 
       fn_in [MAX_FN], 
       fn_out [MAX_FN]; 

} param_t; 

void disp_usage() 
{
  fprintf(stderr, "usage: oaep-rsa --gen <number of bits> --key <key name>\n"); 
  fprintf(stderr, "                --encrypt --key <public key file> -i <in file> -o <out file>\n"); 
  fprintf(stderr, "                --decrypt --key <secret key file> -i <in file> -o <out file>\n"); 
  fprintf(stderr, "                --help\n"); 
}

void disp_help()
{
  fprintf(stdout, "Implementation of OAEP-mode RSA encryption (rfc3447). This program can be\n"); 
  fprintf(stdout, "used to generate a (private, public) key pair and encrypt/decrypt arbitrary\n"); 
  fprintf(stdout, "files.\n\n"); 
}

int parse_options(param_t *options, int argc, const char **argv) 
{
  /* Parse command line options */
  options->fn_in[0] = options->fn_out[0] = '\0';
  strcpy(options->fn_key, "myrsa"); 
  options->n_bits = -1; 
  options->encrypt = 0; 
  options->decrypt = 0; 

  int i; 
  for (i = 1; i < argc; i++) 
  {
    if (strcmp(argv[i], "--help") == 0) {
      disp_help();
      return 0; 
    }
    
    else if (strcmp(argv[i], "--encrypt") == 0) {
      options->encrypt = 1; 
    }
    
    else if (strcmp(argv[i], "--decrypt") == 0) {
      options->decrypt = 1; 
    }

    else if (strcmp(argv[i], "--gen") == 0 && (argc - i) > 1) {
      if (!NUMERIC(argv[i+1][0])) 
        return 0; 
      options->n_bits = atoi(argv[++i]); 
      if (options->n_bits < 0)
        return 0; 
    } 
    
    else if (strcmp(argv[i], "-i") == 0 && (argc - i) > 1) {
      i++; 
      strncpy(options->fn_in, argv[i], MAX_FN); 
    }

    else if (strcmp(argv[i], "-o") == 0 && (argc - i) > 1) {
      i++; 
      strncpy(options->fn_out, argv[i], MAX_FN); 
    }
    
    else if (strcmp(argv[i], "--key") == 0 && (argc - i) > 1) {
      i++; 
      strncpy(options->fn_key, argv[i], MAX_FN - 4); 
    }
    
    else 
      return 0; 
  }
  
  return 1; 
}


int main(int argc, const char **argv)
{
  int err; 
  param_t options; 

  if (!parse_options(&options, argc, argv))
  {
    disp_usage();
    return 0; 
  }

  /* Generate keys */ 
  if (options.n_bits > 0)
  {
    rsa_private_t sk; 
    rsa_public_t pk; 
  
    gmp_randstate_t state; 
    gmp_randinit_default(state); 
    gmp_randseed_ui(state, time(NULL)); 
  
    printf("oaep-rsa: generating RSA parameters ...\n");
    
    rsa_gen(&sk, &pk, state, options.n_bits); 
    printf("oaep-rsa: modulus N supports %d byte messages.\n", pk.n / 8); 
    
    printf("oaep-rsa: writing private key to '%s'.\n", options.fn_key); 
    rsa_write_private(&sk, options.fn_key);
    strcat(options.fn_key, ".pub"); 
    printf("oaep-rsa: writing public key to '%s'.\n", options.fn_key); 
    rsa_write_public(&pk, options.fn_key);

    rsa_free_private(&sk); 
    rsa_free_public(&pk);

    return 0; 
  }

  /* Encrypt a file. */ 
  else if (options.encrypt) 
  {
    rsa_public_t pk;
    strcat(options.fn_key, ".pub"); 
    if (!rsa_read_public(&pk, options.fn_key))
    {
      fprintf(stderr, "oaep-rsa: error: couldn't read key file.\n");  
      return 1; 
    }

    FILE *fd_in = fopen(options.fn_in, "rb");
    if (!fd_in) 
    {
      fprintf(stderr, "oaep-rsa: error: couldn't read input file.\n"); 
      rsa_free_public(&pk); 
      return 1; 
    }

    FILE *fd_out = fopen(options.fn_out, "wb"); 
    if (!fd_out)
    {
      fprintf(stderr, "oaep-rsa: error: couldn't open file for writing.\n"); 
      rsa_free_public(&pk); 
      fclose(fd_in);
      return 1; 
    }

    err = oaep_encrypt_stream(fd_out, fd_in, 0, &pk); 
    if (err == oaepModulusTooSmall)
    {
      fprintf(stderr, "oaep-rsa: error: modulus too small to encrypt.\n"); 
    }

    fclose(fd_in); 
    fclose(fd_out); 
    rsa_free_public(&pk); 

    return err; 
  }

  /* Decrypt a file. */ 
  else if (options.decrypt) 
  {
    rsa_private_t sk;

    if (!rsa_read_private(&sk, options.fn_key))
    {
      fprintf(stderr, "oaep-rsa: error: couldn't read key file.\n");  
      return 1; 
    }

    FILE *fd_in = fopen(options.fn_in, "rb");
    if (!fd_in) 
    {
      fprintf(stderr, "oaep-rsa: error: couldn't read input file.\n"); 
      rsa_free_private(&sk); 
      return 1; 
    }

    FILE *fd_out = fopen(options.fn_out, "wb"); 
    if (!fd_out)
    {
      fprintf(stderr, "oaep-rsa: error: couldn't open file for writing.\n"); 
      rsa_free_private(&sk); 
      fclose(fd_in);
      return 1; 
    }

    err = oaep_decrypt_stream(fd_out, fd_in, 0, &sk); 
    
    if (err == oaepLabelMismatch)
    {
      fprintf(stderr, "oaep-rsa: warning: label mismatch (suggest reject)\n"); 
      err = 0; 
    }
    else if (err == oaepModulusTooSmall)
      fprintf(stderr, "oaep-rsa: error: modulus too small to decrypt.\n"); 
    
    fclose(fd_in); 
    fclose(fd_out); 
    rsa_free_private(&sk); 

    return err; 
  }

  else 
  {
    disp_usage(); 
    return 1; 
  }

}
