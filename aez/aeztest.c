#include "aez.h"
#include <stdio.h>

int main(int argc, const char **argv)
{
  /* Fake key to start. */ 
  aez_key_t K; 
  int i; 
  for (i = 0; i < AEZ_BYTES; i += 4)
  {
    *(uint32_t*)(&K[i]) = 1 << i;
  }

  /* Initialize key vector. */ 
  aez_keyvector_t key; 
  aez_init_keyvector(&key, K, 1 << 4); 
  
  aez_print_key(key.Kecb); 
  aez_print_key(key.Kff0); 
  aez_print_key(key.Kone); 
  
  for (i = 0; i < 4; i++)
  {
    aez_print_key(key.Kmac[i]);
    aez_print_key(key.Kmac1[i]);
  }

  for (i = 0; i < key.msg_length; i++)
  {
    aez_print_key(key.K[i]);
    aez_print_key(key.Khash[i]);
  }


  /* Destroy key vector. */ 
  aez_free_keyvector(&key); 

  return 0; 
}
