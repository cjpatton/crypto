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

static void display_block(const Block X) 
{
  for (int i = 0; i < 4; i ++)
    printf("0x%08x ", X.word[i]); 
}

int main() 
{
  Block X;
  for (int i = 0; i < 16; i++)
    X.byte[i] = i; 
  display_block(X); printf("\n"); 
  set_big_endian(X); 
  display_block(X); printf("\n"); 

  return 0; 
}
