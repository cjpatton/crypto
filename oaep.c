/**
 * oaep.c - Implementation of OAEP-RSA (rfc3447). 
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

#include "oaep.h"
#include "rsa.h"
#include "sha1.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>


  /*
   * Local function prototypes  
   */ 

void disp_pad(const char *pad, size_t lN); 

int oaep_pad(char *pad, const char *message, unsigned long label, 
             size_t lMsg, oaep_context_t *context);
int oaep_unpad(char *message, const char *pad, unsigned long label,
               size_t *lMsg, oaep_context_t *context); 

int oaep_encode(char *pad, oaep_context_t *context);
int oaep_decode(char *pad, oaep_context_t *context); 

const uint8_t *SHA1(const uint8_t *message, int lMsg, oaep_context_t *context);


/* 
 * Function oaep_encrypt
 *
 * Description
 *   OAEP-mode encryption of a (plaintext, label) under an RSA 
 *   public key, using the SHA-1 cryptographic hash function. 
 *   Abort if the message is too long. 
 *
 * Return { oaepSuccess, oaepMsgLength, oaepModulusTooSmall }
 */ 
int oaep_encrypt(char *ciphertext, const char *plaintext, size_t *lCipher, 
                 size_t lMsg, unsigned long label, rsa_public_t *public_key)
{

  oaep_context_t context; 
  context.H = SHA1;
  context.lN = public_key->n / 8;
  context.lSeed = SHA1HashSize; 
  
  char *pad = malloc(context.lN * sizeof(char)); 
  mpz_t M, C; mpz_inits(M, C, NULL); 

  /* Pad */ 
  int err = oaep_pad(pad, plaintext, label, lMsg, &context);
  if (err) 
  {
    mpz_clears(M, C, NULL); 
    free(pad); 
    return err; 
  }

  /* Encode */ 
  err = oaep_encode(pad, &context); 
  if (err)
  {
    mpz_clears(M, C, NULL); 
    free(pad); 
    return err; 
  }
 
  //int i;
  //for (i = 0; i < lN; i++)
  //  printf("%02x ", (unsigned char)pad[i]); 
  //printf("\n"); 

  /* Encrypt */ 
  mpz_import(M, context.lN, -1, sizeof(char), -1, 0, pad);
  rsa_enc(C, M, public_key);
  mpz_export(ciphertext, lCipher, -1, sizeof(char), -1, 0, C);  

  mpz_clears(M, C, NULL); 
  free(pad); 

  return (oaep_err_t)oaepSuccess; 
} // oaep_encrypt()

/* 
 * Function oaep_decryption
 * 
 * Description
 *   OAEP-mode decryption of a ciphertext under an RSA private 
 *   key, using the SHA-1 cryptographic hash function. Abort if 
 *   the ciphertext is too long, or if the label hash in the pad
 *   doesn't match H(label). 
 *
 * Return { oaepSuccess, 
 *          oaepCipherLength, 
 *          oaepLabelMismatch 
 *          oaepModulusTooSmall }
 */
int oaep_decrypt(char *plaintext, const char *ciphertext, size_t *lMsg, 
                 size_t lCipher, unsigned long label, rsa_private_t *secret_key)
{
  oaep_context_t context; 
  context.H = SHA1;
  context.lN = secret_key->n / 8;
  context.lSeed = SHA1HashSize; 

  char *pad = malloc(context.lN * sizeof(char)); 
  mpz_t M, C; 
  mpz_inits(M, C, NULL); 

  /* Decrypt */ 
  mpz_import(C, lCipher, -1, sizeof(char), -1, 0, ciphertext);
  if (mpz_cmp(C, secret_key->N) > 0)
  {
    mpz_clears(M, C, NULL); 
    free(pad); 
    return (oaep_err_t)oaepCipherLength;
  }
  rsa_dec(M, C, secret_key); 
  mpz_export(pad, lMsg, -1, sizeof(char), -1, 0, M); 

  /* Decode */ 
  int err = oaep_decode(pad, &context); 
  if (err)
  {
    mpz_clears(M, C, NULL); 
    free(pad); 
    return err; 
  }

  /* Unpad, verify label */ 
  err = oaep_unpad(plaintext, pad, label, lMsg, &context); 
  if (err) 
  {
    mpz_clears(M, C, NULL); 
    free(pad); 
    return err; 
  }

  mpz_clears(M, C, NULL); 
  free(pad); 

  return (oaep_err_t)oaepSuccess; 
} // oaep_decrypt()
 

/* Function oaep_encrypt_stream
 *
 * Description
 *   Encrypt a file stream under an RSA public key. 
 *
 * Return { oaepSuccess, oaepModulusTooSmall }
 */ 
int oaep_encrypt_stream(FILE *fd_out, FILE *fd_in, unsigned long label, 
                        rsa_public_t *public_key)
{
  oaep_context_t context; 
  context.H = SHA1;
  context.lN = public_key->n / 8;
  context.lSeed = SHA1HashSize; 
  
  long lMsg, lMsgBuff, lCipher, lBuffer = context.lN + 1; 
  lMsgBuff = context.lN - (2 * context.lSeed) - 2; 
  lMsgBuff -= lMsgBuff % context.lSeed; 
    
  if (lMsgBuff - 1 <= 0)
    return (oaep_err_t)oaepModulusTooSmall; 
  
  char *plaintext = malloc(lBuffer * sizeof(char)),
       *ciphertext = malloc(lBuffer * sizeof(char)),
       *pad = malloc(lBuffer * sizeof(char)); 
  memset(ciphertext, 0, sizeof(char) * lBuffer); 
  memset(plaintext, 0, sizeof(char) * lBuffer); 
  memset(pad, 0, sizeof(char) * lBuffer); 

  mpz_t M, C; mpz_inits(M, C, NULL); 

  /* Read next chunk. */ 
  while((lMsg = fread(plaintext, sizeof(char), lMsgBuff - 1, fd_in)))
  { 
    memset(ciphertext, 0, sizeof(char) * lBuffer); 
    memset(pad, 0, sizeof(char) * lBuffer); 
    
    /* Pad, encode, and encrypt. */
    oaep_pad(pad, plaintext, label, lMsg, &context);
    oaep_encode(pad, &context); 
    mpz_import(M, context.lN, -1, sizeof(char), -1, 0, pad);
    rsa_enc(C, M, public_key);
    mpz_export(ciphertext, (size_t *)&lCipher, -1, sizeof(char), -1, 0, C); 
 
    /* Write out encrypted chunk. */ 
    fwrite(ciphertext, sizeof(char), lBuffer, fd_out); 
    
    memset(plaintext, 0, sizeof(char) * lBuffer); 
  }

  mpz_clears(M, C, NULL); 
  free(plaintext);
  free(ciphertext); 
  free(pad); 
  
  return (oaep_err_t)oaepSuccess; 
}

/* 
 * Function oaep_decrypt_stream
 *
 * Description
 *   Decrypt a file stream under an RSA public key.  
 *
 * Return { oaepSuccess, oaepLabelMismatch, oaepModulusTooSmall }
 */ 
int oaep_decrypt_stream(FILE *fd_out, FILE *fd_in, unsigned long label, 
                        rsa_private_t *secret_key)
{
  int err, res = (oaep_err_t)oaepSuccess;
  oaep_context_t context; 
  context.H = SHA1;
  context.lN = secret_key->n / 8;
  context.lSeed = SHA1HashSize; 
  
  long lMsg, lMsgBuff, lCipher, lBuffer = context.lN + 1; 
  lMsgBuff = context.lN - (2 * context.lSeed) - 2; 
  lMsgBuff -= lMsgBuff % context.lSeed; 
  
  if (lMsgBuff - 1 <= 0)
    return (oaep_err_t)oaepModulusTooSmall; 

  char *plaintext = malloc(lBuffer * sizeof(char)),
       *ciphertext = malloc(lBuffer * sizeof(char)),
       *pad = malloc(lBuffer * sizeof(char)); 
  memset(ciphertext, 0, sizeof(char) * lBuffer); 
  memset(plaintext, 0, sizeof(char) * lBuffer); 
  memset(pad, 0, sizeof(char) * lBuffer); 

  mpz_t M, C; mpz_inits(M, C, NULL); 
  
  /* Read next chunk. */ 
  while ((lCipher = fread(ciphertext, sizeof(char), context.lN + 1, fd_in)))
  {
    memset(plaintext, 0, sizeof(char) * lBuffer); 
    memset(pad, 0, sizeof(char) * lBuffer); 
    
    /* Decrypt, decode, and unpad. */ 
    mpz_import(C, lCipher, -1, sizeof(char), -1, 0, ciphertext);
    rsa_dec(M, C, secret_key); 
    mpz_export(pad, (size_t *)&lMsg, -1, sizeof(char), -1, 0, M); 
    oaep_decode(pad, &context); 
    err = oaep_unpad(plaintext, pad, label, (size_t *)&lMsg, &context); 
    if (err == oaepLabelMismatch)
      res = err;

    /* Write out decrypted chunk. */ 
    fwrite(plaintext, sizeof(char), lMsg, fd_out);   
    
    memset(ciphertext, 0, sizeof(char) * lBuffer); 
  }

  mpz_clears(M, C, NULL); 
  free(plaintext);
  free(ciphertext); 
  free(pad); 
 
  return (oaep_err_t)res; 
}



  /* 
   * Local function implementations
   */

void disp_pad(const char *pad, size_t lN) 
{
  int i, padding = 0;
  for (i = 0; i < (int)lN; i++)
  {
    if (pad[i] == '\0')
      padding ++;
    else if (pad[i] != '\0' && padding > 0)
    {
      printf(" ... '\\0' x %d ... %c", padding, pad[i]);
      padding = 0; 
    }
    else printf("%c", pad[i]); 
  }
  if (padding > 0)
    printf(" ... '\\0' x %d\n", padding);
  else 
    printf("\n");
}


/*
 * Function oaep_pad
 *
 * Description
 *   Pad a message, create a hash of label and add it to pad. 
 *   label is converted to a string the length of lSeed. lSeed 
 *   is required to be the output length of the hash function. 
 *   Message is padded to a multiple of of lSeed. Message pad 
 *   is `lN - lSeed * 2 - 2`. 
 */ 
int oaep_pad(char *pad, const char *message, unsigned long label,
             size_t lMsg, oaep_context_t *context)
{
  long lMsgBuff = context->lN - (2 * context->lSeed) - 2; 
  lMsgBuff -= lMsgBuff % context->lSeed; 
  
  if (lMsgBuff - 1 <= 0) 
    return (oaep_err_t)oaepModulusTooSmall; 

  if (lMsg > lMsgBuff - 1)
    return (oaep_err_t)oaepMsgLength; 

  /* Padding */ 
  memset(pad, 0, context->lN * sizeof(char)); 
  memcpy(pad, message, lMsg * sizeof(char)); 
  pad[lMsg] = 1; /* This byte signals the end of the message to be read-> */ 

  /* Hash of label-> */ 
  uitoa(label, (char *)context->buff, 10); 
  memcpy(&pad[lMsgBuff], context->H(
   context->buff, strlen((char *)context->buff), context), context->lSeed); 

  return (oaep_err_t)oaepSuccess;
}

/*
 * Funciton oaep_unpad
 *
 * Description
 *   Unpad message into buffer, check that the hash matches label. 
 */
int oaep_unpad(char *message, const char *pad, unsigned long label,
               size_t *lMsg, oaep_context_t *context)
{
  size_t lMsgBuff = context->lN - (2 * context->lSeed) - 2; 
  lMsgBuff -= lMsgBuff % context->lSeed; 
  size_t lMsgEnd = lMsgBuff; 

  /* Verify hash. */ 
  uitoa(label, (char *)context->buff, 10); 
  const uint8_t *hash = context->H(context->buff, strlen((char *)context->buff), context); 
  
  /* Seek to end of zero pad. */
  while (--lMsgEnd > 0 && pad[lMsgEnd] == 0)
    ;

  /* Copy message to buffer. */ 
  memcpy(message, pad, lMsgEnd * sizeof(char)); 
  *lMsg = lMsgEnd;
  
  //printf("guy   "); 
  //disp_pad_hex(&pad[lMsgBuff], lSeed); 
  //printf("fella "); 
  //disp_pad_hex(hash, lSeed); 

  if (strncmp((const char *)hash, &pad[lMsgBuff], context->lSeed) != 0) 
    return (oaep_err_t)oaepLabelMismatch; 

  return (oaep_err_t)oaepSuccess; 
}


/* 
 * Function oaep_encode
 *
 * Description
 *   Generate seed and encode the pad as described in the OAEP spec. 
 */ 
int oaep_encode(char *pad, oaep_context_t *context)
{
  size_t lMsgBuff = context->lN - (2 * context->lSeed) - 2; 
  lMsgBuff -= lMsgBuff % context->lSeed; 
  
  const char *hash;
  char *seed; 
  int i, j;

  /* Generate seed. */
  seed = malloc(context->lSeed * sizeof(char)); 
  for (i = 0; i < context->lSeed; i++)
    seed[i] = rand() % 256;

  // int k;
  //printf("seed: "); 
  //for (i = 0; i < lSeed; i++)
  //  printf("%02x ", (unsigned char)seed[i]); 
  //printf("\n"); 

  /* Mask messaage and label pad. */
  for (i = 0; i < lMsgBuff + context->lSeed; i += context->lSeed)
  {
    hash = (const char *)context->H((uint8_t *)seed, context->lSeed, context); 
    //printf("%-4d: ", i); 
    //for (k = 0; k < lSeed; k++)
    //  printf("%02x ", (unsigned char)hash[k]); 
    //printf("\n"); 
    for (j = 0; j < context->lSeed; j++)
    {
      pad[i + j] ^= hash[j]; 
    }
    seed[0] ++; 
  }

  /* Mask seed. */
  seed[0] --;
  seed[0] -= lMsgBuff / context->lSeed; 
  hash = (const char *)context->H((uint8_t *)pad, lMsgBuff + context->lSeed, context);
  for (i = 0; i < context->lSeed; i++)
  {
    pad[i + lMsgBuff + context->lSeed] = seed[i] ^ hash[i]; 
  }

  free(seed); 

  return (oaep_err_t)oaepSuccess; 
}

/* 
 * Function oaep_decode
 *
 * Description
 *   Decode pad as described in the OAEP spec. 
 *
 */ 
int oaep_decode(char *pad, oaep_context_t *context)
{
  size_t lMsgBuff = context->lN - (2 * context->lSeed) - 2; 
  lMsgBuff -= lMsgBuff % context->lSeed; 
  
  char *seed;
  const char *hash;
  int i, j;

  hash = (const char *)context->H((uint8_t *)pad, lMsgBuff + context->lSeed, context); 
  seed = malloc(context->lSeed * sizeof(char)); 

  /* Unmask seed. */ 
  for (i = 0; i < context->lSeed; i++)
  {
    seed[i] = pad[i + lMsgBuff + context->lSeed] ^ hash[i]; 
  }
  
  //int k;
  //printf("seed: "); 
  //for (i = 0; i < context.lSeed; i++)
  //  printf("%02x ", (unsigned char)seed[i]); 
  //printf("\n"); 
  
  /* Unmask message and label pad. */
  for (i = 0; i < lMsgBuff + context->lSeed; i += context->lSeed)
  {
    hash = (const char *)context->H((uint8_t *)seed, context->lSeed, context); 
    //printf("%-4d: ", i); 
    //for (k = 0; k < context.lSeed; k++)
    //  printf("%02x ", (unsigned char)hash[k]); 
    //printf("\n"); 
    for (j = 0; j < context->lSeed; j++)
    {
      pad[i + j] ^= hash[j]; 
    }
    seed[0] ++; 
  }

  free(seed); 
  return (oaep_err_t)oaepSuccess; 
}


/*
 *  Funciton SHA1 
 *
 *  Function
 *    One-call interface for SHA1. 
 *
 */
const uint8_t *SHA1(const uint8_t *message, int lMsg, oaep_context_t *context) 
{
  int err = SHA1Reset(&(context->sha)); 
  if (err)
    return NULL;  
  err = SHA1Input(&(context->sha), message, lMsg); 
  if (err) 
    return NULL; 
  err = SHA1Result(&(context->sha), context->hash); 
  if (err) 
    return NULL; 
  return context->hash; 
}
