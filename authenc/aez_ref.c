#include "rijndael-alg-fst.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define INVALID -1
typedef unsigned char byte;
static void rev(byte *src, byte *dst) {
      byte i, tmp[16];
      memcpy(tmp,src,16);
      for (i=0; i<16; i++) dst[i] = tmp[15-i];
}


/* ------------------------------------------------------------------------- */
typedef unsigned char byte;
static void correct_key(byte *src, unsigned nbytes, byte *dst) {
    const union { int x; char e; } l = { 1 };
    if (l.e) {
        u32 i, *s = (u32 *)src, *d = (u32 *)dst;
        for (i=0; i<nbytes/4; i++)
            d[i] = ((s[i] & 0x000000ffu) << 24) | ((s[i] & 0x0000ff00u) <<  8)
                 | ((s[i] & 0x00ff0000u) >>  8) | ((s[i] & 0xff000000u) >> 24);
    }
}

static void xor_bytes(byte *src1, byte *src2, unsigned n, byte *dst) {
    while (n) { n--; dst[n] = src1[n] ^ src2[n]; }
}

/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */

static void double_block(byte *src, byte *dst) {
    byte i, tmp = src[0];
    for (i=0; i<15; i++)
        dst[i] = (byte)((src[i] << 1) | (src[i+1] >> 7));
    dst[15] = (byte)((src[15] << 1) ^ ((tmp >> 7) * 135));
}

/* ------------------------------------------------------------------------- */

static void mult_block(unsigned x, byte *src, byte *dst) {
    byte t[16], r[16];
    rev(src,t); memset(r,0,16);
    for ( ; x; x>>=1) {
        if (x&1) xor_bytes(r,t,16,r);
        double_block(t,t);
    }
    rev(r,dst);
}

/* ------------------------------------------------------------------------- */

/*
C1 C6FE23AF13A3A2043920BAE4DF66DE3F
C2 0FD2EFC0BB1517C1D6143E0DA501486F
C3 16F6310A1916DC27091D517219FBB171
C4 A0552CE664772F2C0AF8FEB11F0BCC75
C5 75604DC2DA7C95BB380BE04B07C87D55
C6 96E868DA0A419725297491FCF3FFC082
C7 E6E60579503649FBF4BE40E7B94D7B7B
*/
static void Extract(byte *K, unsigned kbytes, byte extracted_key[2*16]) {
    u32 aes4_key[4*5], aes4_key_a[4*5], aes4_key_b[4*5];
    byte i, buf[16], C[16], C3[16];
    byte key_constant[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    
    /* Setup key schedules and offsets */
    for (i=0; i<5; i++) memcpy((byte*)aes4_key+i*16,key_constant,16);
    correct_key((byte*)aes4_key, 5*16, (byte*)aes4_key); 
    //for (i = 0; i < 5; i++) {  printf("Them: "); display_block((byte *)aes4_key+i*16); printf("\n"); }
    memset(aes4_key_a,0,80); memset(aes4_key_b,0,80);      
    memset((byte*)aes4_key_a+16, 1, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_a+16, 4);
    memset((byte*)aes4_key_a+32, 2, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_a+32, 4);
    memset((byte*)aes4_key_a+48, 3, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_a+48, 4);
    memset((byte*)aes4_key_b+16, 4, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_b+16, 4);
    memset((byte*)aes4_key_b+32, 5, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_b+32, 4);
    memset((byte*)aes4_key_b+48, 6, 16);
    rijndaelEncryptRound(aes4_key, 10, (byte*)aes4_key_b+48, 4);
    memset(C,7,16); rijndaelEncryptRound(aes4_key, 10, C, 4);
    correct_key((byte*)aes4_key_a+16, 3*16, (byte*)aes4_key_a+16);
    correct_key((byte*)aes4_key_b+16, 3*16, (byte*)aes4_key_b+16);
    //for (i = 0; i < 5; i++) { printf("Them: "); display_block((byte*)aes4_key_b+i*16); printf("\n"); }
    
    mult_block(2,C,buf); xor_bytes(C,buf,16,C3);
    
    memset(extracted_key,0,32);
    for ( ; kbytes >= 16; kbytes-=16, K+=16) {
        xor_bytes(K, C, 16, buf);
        rijndaelEncryptRound(aes4_key_a, 10, buf, 4);
        xor_bytes(extracted_key, buf, 16, extracted_key);
        xor_bytes(K, C, 16, buf);
        rijndaelEncryptRound(aes4_key_b, 10, buf, 4);
        xor_bytes(extracted_key+16, buf, 16, extracted_key+16);
        mult_block(2,C,C);
    }
    if (kbytes) {
        memset(buf,0,16); memcpy(buf,K,kbytes); buf[kbytes]=0x80;
        xor_bytes(buf, C3, 16, buf);
        rijndaelEncryptRound(aes4_key_a, 10, buf, 4);
        xor_bytes(extracted_key, buf, 16, extracted_key);
        memset(buf,0,16); memcpy(buf,K,kbytes); buf[kbytes]=0x80;
        xor_bytes(buf, C3, 16, buf);
        rijndaelEncryptRound(aes4_key_b, 10, buf, 4);
        xor_bytes(extracted_key+16, buf, 16, extracted_key+16);
    }
    
    //printf("----Extract-----\n"); 
    //printf("Them: "); display_block((byte *)extracted_key); printf("\n");
    //printf("Them: "); display_block((byte *)extracted_key+16); printf("\n");
}

/* ------------------------------------------------------------------------- */

static void Expand(byte extracted_key[2*16], byte expanded_key[6*16]) {
    u32 i, aes4_key[4*5];
    
    /* Setup round keys: Adjust and copy K0:K1, then replicate to others */
    memcpy((byte*)aes4_key+0, extracted_key, 32);            /* J:L to K0:K1 */
    mult_block(2, extracted_key, (byte*)aes4_key+32);        /* 2J to K2     */
    memcpy((byte*)aes4_key+48, extracted_key+16, 16);        /* L to K3      */
    mult_block(2, (byte*)aes4_key+32, (byte*)aes4_key+64);   /* 4J to K4     */
    correct_key((byte*)aes4_key,5*16,(byte*)aes4_key);
  
    
    /* Generate bytes */
    memcpy(expanded_key, extracted_key, 32);
    for (i=0; i<4; i++) {
        memset(expanded_key+i*16+32, (char)i, 16);
        rijndaelEncryptRound(aes4_key, 10, expanded_key+i*16+32, 4);
    }
    
    //printf("----Expand-----\n"); 
    //for (i = 0; i < 4; i++) { printf("Them: "); display_block((byte*)expanded_key+i*16+32); printf("\n"); }
}

/* ------------------------------------------------------------------------- */

static void Elf(byte *K, unsigned kbytes, int i, unsigned j,
                                                byte src[16], byte dst[16]) {
    byte extracted_key[2*16], expanded_key[6*16], J[16], L[16], buf[16];
    u32 aes_key[4*11];

    /* Build key schedule for AES. AES4 schedules are contained within */
    Extract(K, kbytes, extracted_key);
    Expand(extracted_key, expanded_key);
    memcpy(J, expanded_key, 16); memcpy(L, expanded_key+16, 16);
    memcpy((byte*)aes_key+0, L, 16);
    memcpy((byte*)aes_key+16, J, 16);
    mult_block(2,(byte*)aes_key+16,(byte*)aes_key+32);
    mult_block(2,(byte*)aes_key+32,(byte*)aes_key+48);
    memcpy((byte*)aes_key+64, expanded_key+32, 64);
    memcpy((byte*)aes_key+128, expanded_key+32, 48);
    correct_key((byte*)aes_key,11*16,(byte*)aes_key);
  
    //printf("----Key schedule----\n"); 
    //for (unsigned fella = 0; fella < 11; fella++) { printf("Them: "); display_block((byte *)&aes_key[fella * 4]); printf("\n"); }
    //printf("----Blockcipher (%d, %d)----\n", i, j); 
    
    /* Encipher */
    mult_block(j%8, J, buf);
    xor_bytes(buf, src, 16, buf);
    if (i < 0) {
       rijndaelEncrypt(aes_key, 10, buf, dst);
    }
    else {
        u32 aes4_key[4*5];
        memcpy((byte*)aes4_key, (byte*)aes_key+64+i*16, 64);
        memset((byte*)aes4_key+64, 0, 16);
        if ((i > 0) && (j > 0)) {
            for ( ; j > 8; j-=8) 
             {mult_block(2,L,L);  /* L = 2^((j-1)/8) L */
              /*printf("Them\n");*/ }
            xor_bytes(buf, L, 16, buf);
        }
        rijndaelEncryptRound(aes4_key, 10, buf, 4);
        memcpy(dst, buf, 16);
    }
}

/* ------------------------------------------------------------------------- */

static void AHash(byte *K, unsigned kbytes, byte *A,
                                            unsigned abytes, byte *result) {
    byte buf[16], sum[16];
    unsigned j;
    
    memset(sum,0,16);
    for (j=0; abytes >= 16; abytes -= 16, A += 16, j += 1) {
        Elf(K,kbytes,3,j,A,buf); xor_bytes(sum, buf, 16, sum);
    }
    if (abytes) {
        memset(buf,0,16); memcpy(buf,A,abytes); buf[abytes]=0x80;
        Elf(K,kbytes,1,0,buf,buf);
        xor_bytes(sum, buf, 16, result);
    } else
        memcpy(result, sum, 16);
}

/* ------------------------------------------------------------------------- */

static void AMac(byte *K, unsigned kbytes, byte *A,
                                            unsigned abytes, byte *result) {
    byte buf[16];
    AHash(K, kbytes, A, abytes, buf); 
    Elf(K,kbytes,-1,5,buf,result);
}

/* ------------------------------------------------------------------------- */

/* Set d=0 for EncipherEME4 and d=1 for DecipherEME4 */
static void CipherEME4(byte *K, unsigned kbytes, byte *T, unsigned tbytes,
                        byte *in, unsigned inbytes, unsigned d, byte *out) {
    byte tmp[16], Delta[16], X[16], Y[16], S[16];
    byte *in_orig = in, *out_orig = out;
    unsigned j, inbytes_orig = inbytes;
    
    memset(X,0,16); memset(Y,0,16);
    AHash(K, kbytes, T, tbytes, Delta);
    //printf("Them: "); display_block(Delta); printf("\n"); 
    
    /* Pass 1 over in[32..], store intermediate values in out[32..] */
    inbytes = inbytes_orig - 32; out = out_orig + 32; in = in_orig + 32;
    for (j=1; inbytes >= 32; j++, inbytes-=32, in+=32, out+=32) {
        Elf(K, kbytes, 1, j, in+16, tmp); xor_bytes(in, tmp, 16, out);
        Elf(K, kbytes, 0, 0, out, tmp); xor_bytes(in+16, tmp, 16, out+16);
        xor_bytes(out+16, X, 16, X);
    }
    
    /* Finish X calculation */
    if (inbytes >= 16) {
        Elf(K, kbytes, 0, 3, in, tmp); xor_bytes(X, tmp, 16, X);
        inbytes -= 16; in += 16; out += 16;
        memset(tmp,0,16); memcpy(tmp,in,inbytes); tmp[inbytes] = 0x80;
        Elf(K, kbytes, 0, 4, tmp, tmp); xor_bytes(X, tmp, 16, X);
    } else if (inbytes > 0) {
        memset(tmp,0,16); memcpy(tmp,in,inbytes); tmp[inbytes] = 0x80;
        Elf(K, kbytes, 0, 3, tmp, tmp); xor_bytes(X, tmp, 16, X);
    }
    
    /* Calculate S */
    xor_bytes(Delta, in_orig, 16, out_orig);
    xor_bytes(X, in_orig+16, 16, out_orig+16);
    Elf(K, kbytes, 0, 1+d, out_orig+16, tmp);
    xor_bytes(out_orig, tmp, 16, out_orig);
    Elf(K, kbytes, -1, 1+d, out_orig, tmp);
    xor_bytes(out_orig+16, tmp, 16, out_orig+16);
    xor_bytes(out_orig, out_orig+16, 16, S);
  
   
    /* Pass 2 over intermediate values in out[32..]. Final values written */
    inbytes = inbytes_orig - 32; out = out_orig + 32; in = in_orig + 32;
    for (j=1; inbytes >= 32; j++, inbytes-=32, in+=32, out+=32) {
        Elf(K, kbytes, 2, j, S, tmp);
        xor_bytes(out, tmp, 16, out); xor_bytes(out+16, tmp, 16, out+16);
        xor_bytes(out, Y, 16, Y);
        Elf(K, kbytes, 0, 0, out+16, tmp); xor_bytes(out, tmp, 16, out);
        Elf(K, kbytes, 1, j, out, tmp); xor_bytes(out+16, tmp, 16, out+16);
        memcpy(tmp, out, 16); memcpy(out, out+16, 16); memcpy(out+16, tmp, 16);
    }

    /* Finish Y calculation and finish encryption of tail bytes */
    if (inbytes >= 16) {
        Elf(K, kbytes, -1, 3, S, tmp); xor_bytes(in, tmp, 16, out);
        Elf(K, kbytes, 0, 3, out, tmp); xor_bytes(Y, tmp, 16, Y);
        inbytes -= 16; in += 16; out += 16;
        Elf(K, kbytes, -1, 4, S, tmp); xor_bytes(in, tmp, inbytes, tmp);
        memcpy(out,tmp,inbytes);
        memset(tmp+inbytes,0,16-inbytes); tmp[inbytes] = 0x80;
        Elf(K, kbytes, 0, 4, tmp, tmp); xor_bytes(Y, tmp, 16, Y);
    } else if (inbytes > 0) {
        Elf(K, kbytes, -1, 3, S, tmp); xor_bytes(in, tmp, inbytes, tmp);
        memcpy(out,tmp,inbytes);
        memset(tmp+inbytes,0,16-inbytes); tmp[inbytes] = 0x80;
        Elf(K, kbytes, 0, 3, tmp, tmp); xor_bytes(Y, tmp, 16, Y);
    }
    
    /* Finish encryption of first two blocks */
    Elf(K, kbytes, -1, 2-d, out_orig+16, tmp);
    xor_bytes(out_orig, tmp, 16, out_orig);
    Elf(K, kbytes, 0, 2-d, out_orig, tmp);
    xor_bytes(out_orig+16, tmp, 16, out_orig+16);
    xor_bytes(Y, out_orig, 16, out_orig);
    xor_bytes(Delta, out_orig+16, 16, out_orig+16);
    memcpy(tmp, out_orig, 16);
    memcpy(out_orig, out_orig+16, 16);
    memcpy(out_orig+16, tmp, 16);
}

/* ------------------------------------------------------------------------- */

/* Set d=0 for EncipherFF0 and d=1 for DecipherFF0 */
static void CipherFF0(byte *K, unsigned kbytes, byte *T, unsigned tbytes,
                        byte *in, unsigned inbytes, unsigned d, byte *out) {
    unsigned rounds,i,j=6,k;
    int step;
    byte mask=0x00, pad=0x80, Delta[16], L[16], R[16], buf[32];
    AHash(K, kbytes, T, tbytes, Delta);
    if      (inbytes==1) rounds=24;
    else if (inbytes==2) rounds=16;
    else if (inbytes<16) rounds=10;
    else {          j=5; rounds=8; }
    /* Split (inbytes*8)/2 bits into L and R. Beware: May end in nibble. */
    memcpy(L, in,           (inbytes+1)/2);
    memcpy(R, in+inbytes/2, (inbytes+1)/2);
    if (inbytes&1) {                     /* Must shift R left by half a byte */
        for (i=0; i<inbytes/2; i++)
            R[i] = (byte)((R[i] << 4) | (R[i+1] >> 4));
        R[inbytes/2] = (byte)(R[inbytes/2] << 4);
        pad = 0x08; mask = 0xf0;
    }
    if (d) {
        if (inbytes < 16) {
            memset(buf,0,16); memcpy(buf,in,inbytes); buf[0] |= 0x80;
            xor_bytes(Delta, buf, 16, buf);
            Elf(K, kbytes,0,7,buf,buf);
            L[0] ^= (buf[0] & 0x80);
        }
        i = rounds-1; step = -1;
    } else {
        i = 0; step = 1;
    }
    for (k=0; k<rounds/2; k++,i=(unsigned)((int)i+2*step)) {
        memset(buf, 0, 16);
        memcpy(buf,R,(inbytes+1)/2);
        buf[inbytes/2] = (buf[inbytes/2] & mask) | pad;
        xor_bytes(buf, Delta, 16, buf);
        buf[15] ^= (byte)i;
        Elf(K, kbytes,0,j,buf,buf);
        xor_bytes(L, buf, 16, L);

        memset(buf, 0, 16);
        memcpy(buf,L,(inbytes+1)/2);
        buf[inbytes/2] = (buf[inbytes/2] & mask) | pad;
        xor_bytes(buf, Delta, 16, buf);
        buf[15] ^= (byte)((int)i+step);
        Elf(K, kbytes,0,j,buf,buf);
        xor_bytes(R, buf, 16, R);
    }
    memcpy(buf,           R, inbytes/2);
    memcpy(buf+inbytes/2, L, (inbytes+1)/2);
    if (inbytes&1) {
        for (i=inbytes-1; i>inbytes/2; i--)
            buf[i] = (byte)((buf[i] >> 4) | (buf[i-1] << 4));
        buf[inbytes/2] = (byte)((L[0] >> 4) | (R[inbytes/2] & 0xf0));
    }
    memcpy(out,buf,inbytes);
    if ((inbytes < 16) && !d) {
        memset(buf+inbytes,0,16-inbytes); buf[0] |= 0x80;
        xor_bytes(Delta, buf, 16, buf);
        Elf(K, kbytes,0,7,buf,buf);
        out[0] ^= (buf[0] & 0x80);
    }
}

/* ------------------------------------------------------------------------- */

static void Encipher(byte *K, unsigned kbytes, byte *T, unsigned tbytes,
                                    byte *in, unsigned inbytes, byte *out) {
    if (inbytes == 0) return;
    if (inbytes < 32) CipherFF0(K, kbytes, T, tbytes, in, inbytes, 0, out);
    else              CipherEME4(K, kbytes, T, tbytes, in, inbytes, 0, out);
}

/* ------------------------------------------------------------------------- */

static void Decipher(byte *K, unsigned kbytes, byte *T, unsigned tbytes,
                                    byte *in, unsigned inbytes, byte *out) {
    if (inbytes == 0) return;
    if (inbytes < 32) CipherFF0(K, kbytes, T, tbytes, in, inbytes, 1, out);
    else              CipherEME4(K, kbytes, T, tbytes, in, inbytes, 1, out);
}

/* ------------------------------------------------------------------------- */

static void Format(byte *N, unsigned nbytes, byte *AD, unsigned adbytes,
                                unsigned abytes, byte **T, unsigned *tbytes) {
    if (nbytes <= 12) {
        byte *res = (byte *)malloc(adbytes+16);
        memset(res,0,16);
        res[0] = (byte)(nbytes == 12 ? abytes | 0x40 : abytes);
        memcpy(res+4, N, nbytes);
        if (nbytes < 12) res[nbytes+4] = 0x80;
        memcpy(res+16, AD, adbytes);
        *tbytes = adbytes+16;
        *T = res;
    } else {
        unsigned padbytes = 16 - (adbytes % 16);
        byte *res = (byte *)malloc(12+nbytes+adbytes+padbytes);
        res[0] = (byte)(abytes | 0x80);
        res[1] = res[2] = res[3] = 0;
        memcpy(res+4, N, 12);
        memcpy(res+16, AD, adbytes);
        res[16+adbytes] = 0x80;
        memset(res+16+adbytes+1,0,padbytes-1);
        memcpy(res+16+adbytes+padbytes,N+12,nbytes-12);
        memset(res+4+nbytes+adbytes+padbytes, 0, 4);
        res[8+nbytes+adbytes+padbytes] = (byte)(nbytes >> 24);
        res[9+nbytes+adbytes+padbytes] = (byte)(nbytes >> 16);
        res[10+nbytes+adbytes+padbytes] = (byte)(nbytes >> 8);
        res[11+nbytes+adbytes+padbytes] = (byte)nbytes;
        *tbytes = 12+nbytes+adbytes+padbytes;
        *T = res;
    }
}

/* ------------------------------------------------------------------------- */

int Decrypt(byte *K, unsigned kbytes, byte *N, unsigned nbytes,
            byte *AD, unsigned adbytes, byte *C, unsigned cbytes,
            unsigned abytes, byte *M) {
    byte *T, *X, sum=0;
    unsigned tbytes,i;
    if (cbytes < abytes) return -1;
    Format(N, nbytes, AD, adbytes, abytes, &T, &tbytes);
    if (cbytes==abytes) {
        byte buf[16];
        AMac(K, kbytes, T, tbytes, buf);
        for (i=0; i<abytes; i++) sum |= (buf[i] ^ C[i]);
    } else {
        X = (byte *)malloc(cbytes);
        Decipher(K, kbytes, T, tbytes, C, cbytes, X);
        for (i=0; i<abytes; i++) sum |= X[cbytes-abytes+i];
        if (sum==0) memcpy(M,X,cbytes-abytes);
        free(X);
    }
    free(T);
    return (sum == 0 ? 0 : INVALID);  /* return 0 if valid, -1 if invalid */
}

/* ------------------------------------------------------------------------- */

void Encrypt(byte *K, unsigned kbytes, byte *N, unsigned nbytes,
             byte *AD, unsigned adbytes, byte *M, unsigned mbytes,
             unsigned abytes, byte *C) {
    byte buf[16], *T, *X;
    unsigned tbytes;
    Format(N, nbytes, AD, adbytes, abytes, &T, &tbytes);
  
    //printf("Their tag: "); 
    //for (unsigned i = 0; i < tbytes; i++)
    //  printf("%02x", T[i]); 

    if (mbytes==0) {
        AMac(K, kbytes, T, tbytes, buf);
        memcpy(C,buf,abytes);
    } else {
        X = (byte *)malloc(mbytes+abytes);
        memcpy(X, M, mbytes); memset(X+mbytes,0,abytes);
        Encipher(K, kbytes, T, tbytes, X, mbytes+abytes, X);
        memcpy(C, X, mbytes+abytes);
        free(X);
    }
    free(T);
}


static void display_block(const  byte *X) 
{
  for (int i = 0; i < 4; i ++)
    printf("0x%08x ", *(uint32_t *)&X[i*4]); 
}
void verify() 
{
  byte  key [] = "One day we will.", nonce [] = "Things are occuring!"; 
  
  byte sum [16]; memset(sum, 0, 16);  

  unsigned key_bytes = strlen((const char *)key), 
           nonce_bytes = strlen((const char *)nonce), 
           auth_bytes = 16, i, res, msg_len = 1001;  

  byte *message = malloc(auth_bytes + msg_len); 
  byte *ciphertext = malloc(auth_bytes + msg_len); 
  byte *plaintext = malloc(auth_bytes + msg_len); 
  memset(ciphertext, 0, msg_len); 
  memset(message, 0, msg_len); 
  
  for (i = 0; i < msg_len; i++)
  {
    Encrypt(key, key_bytes, nonce, nonce_bytes, 
            nonce, nonce_bytes, message, i, auth_bytes, ciphertext); 
    xor_bytes(sum, ciphertext, 16, sum); 
  
    res = Decrypt(key, key_bytes, nonce, nonce_bytes, 
            nonce, nonce_bytes, ciphertext, i + auth_bytes, auth_bytes, plaintext); 

    if (res == INVALID)
      printf("invalid\n");

    if (memcmp(plaintext, message, i) != 0)
      printf("msg length %d: plaintext mismatch!\n", i + auth_bytes); 
  }
  display_block(sum); printf("\n");
  free(message); 
  free(ciphertext); 
  free(plaintext); 
}


int main()
{
  verify(); 


  return 0; 
}
