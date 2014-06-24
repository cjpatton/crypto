#include "aez.h"
#include "../cipher/aes.h"
#include "rijndael-alg-fst.h"
#include <stdio.h>
#include <string.h>

void unit_test(const uint8_t *message, const uint8_t *tag, 
               size_t msg_bytes, size_t tag_bytes, aez_keyvector_t *key);

void dump_block(const uint8_t *X, int margin);

void dump_keys(aez_keyvector_t *key);

void show_cipher(const uint8_t *message, uint8_t *ciphertext, uint8_t *plaintext, size_t bytes);

uint8_t bigtext [] = "Encryption and decryption. See Figure 3. To encrypt a string M we augment it with an\
authenticator —a block of abytes zero bytes—and encipher the resulting string, tweaking this\
enciphering scheme with a tweak formed from AD, N , and the parameters. These are encoded in\
a manner that enhances the efficiency of their processing (in particular, AD always starts with the\
second block and ends on a block boundary, and the nonce is packed into the first block as long as\
this is possible). Next we encipher the augmented message. To decrypt a ciphertext C we reverse\
the process, verifying the presence of the all-zero authenticator.\
For the users’ convenience, keys of any length are allowed. Using procedure Extract, they are first\
processed into 16-byte strings using an almost-universal hash function with a fixed but “random”\
key, an approach rooted in the leftover hash lemma [2, 11, 15]. The Extract algorithm is based on\
CMAC and NIST recommendation SP 800-56C [8]. Keys of 128 bits are processed more efficiently\
than other keys.\
Alternative processing is performed at lines 104 and 113 if the message M is empty. In this case\
we do need not to encipher anything; the user is only requesting a message-authentication service.\
This saves some time when AEZ is used as a MAC. The MAC we use to satisfy the user’s request\
is a PRF we call it AMAC. Besides taking in the key and the string that is being authenticated,\
AMAC also takes in a number i ∈ [0..4], which is regarded as part of the domain of the PRF. The\
argument is used to conceptually provide a variety of MACS, each as efficient as the other. We will\
meet AMAC again; it is used for multiple purposes within AEZ.\
Enciphering and deciphering. Messages are enciphered by one of four different methods. Dis-\
patch occurs in algorithm Encipher of Figure 3. Strings of length 0 or 16 bytes are handled by\
Encipher itself. Strings of 1–15 bytes are enciphered using the Feistel-based method FF0, realized in\
algorithm EncipherFF0. Strings of 17 bytes or more are enciphered using a method we call MEM,\
realized in the algorithm EncipherMEM of Figure 4. In all of these routines, when encountering a\
key derived from K—any of Kecb, Kff0, Kone, Kmac, Kmac ′ , Khashi , or Ki —the named key is\
implicitly defined from K using the procedure MakeSubkeyVectors of Figure 7.\
Roughly following FFX [4, 12], algorithm EncipherFF0 uses ten rounds of a balanced Feistel net-\
work. (More rounds are used for strings shorter than three bytes. Specifically, we use 24 ro\
nds for one-byte strings, and 16 rounds for two-byte strings.) The round function is based on AES. We\
use the four-round version of it for this purpose. This is implicit in the pseudocode, embedded in\
the fact that Kff0 is a five-block key. Another novel feature of EncipherFF0 compared to FFX is\
the swapping of a fixed pair of points when a key-dependent, tweak-dependent, length-dependent\
pseudorandom bit comes out to be 1. The same trick, without the tweak or length dependency,\
has been used before [27] to address the well-known fact that Feistel can only generate even per-\
mutations [17]."; 

int main(int argc, const char **argv)
{
  
  uint8_t message [4096]; 
  uint8_t plaintext [4096]; 
  uint8_t ciphertext [4096]; 
  //uint8_t hash [AEZ_BYTES]; 
  //uint8_t mac [AEZ_BYTES]; 
  uint8_t user_key [] = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6};  
  uint8_t tag [] = "I think this is a fine tag, but it could be a bit more meaningful."; 
  
  aez_keyvector_t key; 
  aez_init_keyvector(&key, user_key); 
  memset(message, 0, 4096); 
  strcpy((char *)message, "01234567789abcdeAww."); 

  size_t msg_bytes = 3099;
  //int i =2 ; 
  printf("Message bytes: %d of %d\n", (int)msg_bytes, 
      (int)strlen((char *)bigtext));


  /* ------------------------------------------------------------------ */
  printf("Us ... \n"); 
  
  // Cipher
  memset(plaintext, 0, 4096); 
  memset(ciphertext, 0, 4096); 
  aez_encipher(ciphertext, bigtext, tag, msg_bytes, strlen((char *)tag), &key); 
  aez_decipher(plaintext, ciphertext, tag, msg_bytes, strlen((char *)tag), &key); 
  show_cipher(bigtext, ciphertext, plaintext, msg_bytes);  

  // AMAC
  //aez_amac(mac, bigtext, msg_bytes, &key, i); 
  //printf("MAC: "); aez_print_block((uint32_t *)mac, 0); 

  // AHash
  //memset(hash, 0, AEZ_BYTES); 
  //aez_ahash(hash, bigtext, strlen((char *)bigtext), &key); 
  //printf("Hash: "); aez_print_block((uint32_t *)hash, 0); 

  // AES
  //aes_encrypt(message, ciphertext, (uint32_t *)key.enc.Klong, 10);  
  //aes_decrypt(ciphertext, plaintext, (uint32_t *)key.dec.Klong, 10);  
  //printf("message:    %s\n", plaintext); 
  //printf("plaintext:  "); aez_print_block((uint32_t *)plaintext, 0);
  //printf("ciphertext: "); aez_print_block((uint32_t *)ciphertext, 0);

  /* ------------------------------------------------------------------ */
  printf("\n ... and them.\n"); 
  uint32_t encKlong [11 * 4]; 
  uint32_t decKlong [11 * 4]; 
  rijndaelKeySetupEnc(encKlong, user_key, 128); 
  rijndaelKeySetupDec(decKlong, user_key, 128); 
  
  // Cipher
  memset(plaintext, 0, 4096); 
  memset(ciphertext, 0, 4096); 
  Cipher(user_key, tag, strlen((char *)tag), bigtext, msg_bytes, 0, ciphertext);
  Cipher(user_key, tag, strlen((char *)tag), ciphertext, msg_bytes, 1, plaintext);
  show_cipher(bigtext, ciphertext, plaintext, msg_bytes);  
  

  // AMAC
  //AMAC(user_key, bigtext, msg_bytes, i, mac); 
  //printf("MAC: "); aez_print_block((uint32_t *)mac, 0); 
  
  // AHash
  //memset(hash, 0, AEZ_BYTES); 
  //AHash(user_key, bigtext, strlen((char *)bigtext), hash); 
  //printf("Hash: "); aez_print_block((uint32_t *)hash, 0); 

  // AES 
  //rijndaelEncrypt(encKlong, 10, message, ciphertext); 
  //rijndaelDecrypt(decKlong, 10, ciphertext, plaintext); 
  //printf("message:    %s\n", plaintext); 
  //printf("plaintext:  "); aez_print_block((uint32_t *)plaintext, 0);
  //printf("ciphertext: "); aez_print_block((uint32_t *)ciphertext, 0);



  return 0; 
}


void unit_test(const uint8_t *message, const uint8_t *tag, 
               size_t msg_bytes, size_t tag_bytes, aez_keyvector_t *key)
{
  static int test_no = 1; 
  int bytes; 
  
  uint8_t *ciphertext = malloc(msg_bytes + AEZ_BYTES); 
  uint8_t *plaintext  = malloc(msg_bytes + AEZ_BYTES);  
  memset(plaintext, 0, msg_bytes + AEZ_BYTES); 
  memset(ciphertext, 0, msg_bytes + AEZ_BYTES); 
  
  printf("Test #%d (%d bytes)\n", test_no++, (int)msg_bytes); 
  
  int res = aez_encipher(ciphertext, message, tag, msg_bytes, tag_bytes, key);  
  if (res < 0)
  {
    if (res == aez_NOT_IMPLEMENTED)
      printf(" Feature not implemented.\n\n"); 
    else 
      printf(" An error occured!\n\n"); 
    free(ciphertext); 
    free(plaintext);
    return; 
  }
  
  bytes = res; 
  aez_decipher(plaintext, ciphertext, tag, 
               bytes, tag_bytes, key); 
  
  show_cipher(message, ciphertext, plaintext, bytes);

  free(ciphertext);
  free(plaintext); 
}


void show_cipher(const uint8_t *message, uint8_t *ciphertext, uint8_t *plaintext, size_t bytes)
{
  int i, j;
  printf(" Message:    "); 
  aez_print_block((uint32_t *)message, 0);
  for (i = AEZ_BYTES; i < bytes; i += AEZ_BYTES)
    aez_print_block((uint32_t *)&message[i], 13);
  
  printf("\n Ciphertext: "); 
  aez_print_block((uint32_t *)ciphertext, 0);
  for (i = AEZ_BYTES; i < bytes; i += AEZ_BYTES)
    aez_print_block((uint32_t *)&ciphertext[i], 13);

  //plaintext[4] = 'q';
  for (j = 0; j < bytes; j++)
  {
    if (plaintext[j] != message[j])
    {
      printf("\n Message-plaintext mismatch!\n"); 
      printf(" Plaintext:  "); 
      aez_print_block((uint32_t *)plaintext, 0);
      for (i = AEZ_BYTES; i < bytes; i += AEZ_BYTES)
        aez_print_block((uint32_t *)&plaintext[i], 13);
      printf("\n"); 
      break;
    }
  }

  if (j == bytes)
    printf("\n No problem.\n\n"); 
}


void dump_block(const uint8_t *X, int margin)
{
  int i;
  while (margin--)
    printf(" ");
  for (i = AEZ_BYTES - 4; i >= 0; i -= 4)
    printf("0x%02x%02x%02x%02x ", X[i+3], X[i+2], X[i+1], X[i]); 
  printf("\n"); 
}

void dump_keys(aez_keyvector_t *key)
{
  int j, i;
  printf("Key schedules (AES round keys)\n\n"); 
  printf("Kecb "); 
  XOR_BLOCK(key->enc.Klong[0], key->Kecb); 
  XOR_BLOCK(key->enc.Klong[10], key->Kecb); 
  aez_print_block(key->enc.Klong[0], 0); 
  for (i = 1; i < 11; i++)
    aez_print_block(key->enc.Klong[i], 5); 
  XOR_BLOCK(key->enc.Klong[0], key->Kecb); 
  XOR_BLOCK(key->enc.Klong[10], key->Kecb); 
  
  printf("\nKff0 ");
  XOR_BLOCK(key->enc.Kshort[0], key->Kff0); 
  aez_print_block(key->enc.Kshort[0], 0);
  for (i = 1; i < 5; i++)
    aez_print_block(key->enc.Kshort[i], 5);
  XOR_BLOCK(key->enc.Kshort[0], key->Kff0); 
  
  printf("\nKone "); 
  XOR_BLOCK(key->enc.Klong[0], key->Kone); 
  XOR_BLOCK(key->enc.Klong[10], key->Kone); 
  aez_print_block(key->enc.Klong[0], 0); 
  for (i = 1; i < 11; i++)
    aez_print_block(key->enc.Klong[i], 5); 
  XOR_BLOCK(key->enc.Klong[0], key->Kone); 
  XOR_BLOCK(key->enc.Klong[10], key->Kone); 

  for (j = 0; j < 4; j++) 
  {
    printf("\n Kmac[%d] ", j);
    XOR_BLOCK(key->enc.Klong[0], key->Kmac[j]); 
    XOR_BLOCK(key->enc.Klong[10], key->Kmac[j]); 
    aez_print_block(key->enc.Klong[0], 0); 
    for (i = 1; i < 11; i++)
      aez_print_block(key->enc.Klong[i], 9); 
    XOR_BLOCK(key->enc.Klong[0], key->Kmac[j]); 
    XOR_BLOCK(key->enc.Klong[10], key->Kmac[j]); 
  }
  
  for (j = 0; j < 4; j++) 
  {
    printf("\n Kmac'[%d] ", j);
    XOR_BLOCK(key->enc.Klong[0], key->Kmac1[j]); 
    XOR_BLOCK(key->enc.Klong[10], key->Kmac1[j]); 
    aez_print_block(key->enc.Klong[0], 0); 
    for (i = 1; i < 11; i++)
      aez_print_block(key->enc.Klong[i], 10); 
    XOR_BLOCK(key->enc.Klong[0], key->Kmac1[j]); 
    XOR_BLOCK(key->enc.Klong[10], key->Kmac1[j]); 
  }

//  printf("\n\nVectors\n\n"); 
//  for (j = 0; j < key->msg_length; j++) 
//  {
//    printf(" K[%-4d] ", j);
//    aez_print_block(key->K[j], 0); 
//  }
//
//  for (j = 0; j < key->msg_length; j++) 
//  {
//    printf("\n Khash[%-4d] ", j);
//    XOR_BLOCK(key->enc.Kshort[0], key->Khash[j]); 
//    aez_print_block(key->enc.Kshort[0], 0);
//    for (i = 1; i < 5; i++)
//      aez_print_block(key->enc.Kshort[i], 13);
//    XOR_BLOCK(key->enc.Kshort[0], key->Khash[j]); 
//  }
}
