#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


typedef uint8_t Byte; 
typedef uint32_t Word; 

typedef union {
  Byte byte [16]; 
  Word word [4]; 
} Block; 

typedef Byte OBlock [16]; 

#define reverse_u32(n) ( \
 ((n & 0x000000ffu) << 24) | \
 ((n & 0x0000ff00u) <<  8) | \
 ((n & 0x00ff0000u) >>  8) | \
 ((n & 0xff000000u) >> 24) \
)

#define set_big_endian(X) { \
  X.word[0] = reverse_u32(X.word[0]); \
  X.word[1] = reverse_u32(X.word[1]); \
  X.word[2] = reverse_u32(X.word[2]); \
  X.word[3] = reverse_u32(X.word[3]); \
}

#define Oreverse_u32(dst, src) { \
    *u32_ptr(dst) = ((*u32_ptr(src) & 0x000000ffu) << 24) | \
                    ((*u32_ptr(src) & 0x0000ff00u) <<  8) | \
                    ((*u32_ptr(src) & 0x00ff0000u) >>  8) | \
                    ((*u32_ptr(src) & 0xff000000u) >> 24); \
}

#define u8_ptr(X) ((uint8_t *)X)
#define u32_ptr(X) ((uint32_t *)X) 
   
#define Oset_big_endian(X) { \
 Oreverse_u32(&u8_ptr(X)[0],  &u8_ptr(X)[0]);  \
 Oreverse_u32(&u8_ptr(X)[4],  &u8_ptr(X)[4]);  \
 Oreverse_u32(&u8_ptr(X)[8],  &u8_ptr(X)[8]);  \
 Oreverse_u32(&u8_ptr(X)[12], &u8_ptr(X)[12]); \
      }


static void display_block(const Block X) 
{
  int i; 
  for (i = 0; i < 4; i ++)
    printf("0x%08x ", X.word[i]); 
}

static void Odisplay_block(const Byte X []) 
{
  int i; 
  for (i = 0; i < 4; i ++)
    printf("0x%08x ", *(uint32_t *)&X[i * 4]); 
}

int main() 
{
  int i;
  Block X;
  for (i = 0; i < 16; i++)
    X.byte[i] = i; 
  
  Odisplay_block(X.byte); printf("\n"); 
  set_big_endian(X); 
  Odisplay_block(X.byte); printf("\n"); 
  
  OBlock Y;
  for (i = 0; i < 16; i++)
    Y[i] = i; 
  
  Odisplay_block(Y); printf("\n"); 
  Oset_big_endian(Y); 
  Odisplay_block(Y); printf("\n"); 

  printf("%08x\n", &X); 
  printf("%08x\n", X.byte); 
  printf("%08x\n", X.word); 

  return 0; 
}
