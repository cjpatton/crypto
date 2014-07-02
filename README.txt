This is a collection of cryptographic algorithms and tools
written in order to deepen my own understanding. They aren't
intended for use in the wild. All except the SHA1 and AES 
implementations (see below) are my own work.   


aez/

  A compliant, platform-independent implementation of the AEZ 
  authenticated encryption scheme v 1.1.  

  TODO 
    - aez.h - ABYTES, EXTNS
    - Test to see if aez_encipher works in place.  
  
  NOTES
    
    - {En,De}cipherMEM(): I expect the input size to be greater
      than 16 bytes long. 

    - AES4 doesn't appear to be invertible? Well, it is if the 
      key schedule is set up in the proper way. Kshort in the 
      keyvector is formed from Klong, the complete schedule for
      10-round AES.  

    - It looks safe to pass in the same memory reference for `in` 
      and `out` for the AES cipher. 
      
  aez_bm.c 

    - Reference implementation of AEZ wrtten by Ted Krovetz. main()
      has some stuff for validating my implementation.

  aez_ni_bm.c

    - Optimized AEZ implementation using the x86 AES instructions, 
      written by Ted Krovetz. Modified main() to benchmark my 
      implementation. 

  rijndael-alg-fst.{h,c}
    
    - A public domain implementation of AES, provided with the 
      reference implementation of AEZ. 



oaep-rsa.c

  Generate RSA keys and encrypt / decrypt files under OAEP-RSA, 
  using the SHA-1 cryptographic hash funciton. 


asym/ 

  oaep.{h,c}

    The optimal asymmetric encryption padding scheme invented by 
    Bellare and Rogaway (RFC3447). This is meant to provide a 
    realizable RSA-based encryption scheme, provably secure in the 
    random oracle model. 
    
    TODO 
    
      - Push all integrity checks up stream to avoid redundencies.
      - `lMsgBuff % lSeed == 0` is a requirement. When producing
        the mask, we do `++(char)seed[0]` for each chunk. Obviously 
        the number of chunks is limited to 256. Maybe this should be
        stated explicitly. 

  rsa.{h,c}
    
    Textbook RSA, using the GMP library (http://gmplib.org) for 
    arithmetic over arbitrary precision integers. The keys are 
    generated from n-bit primes p and q, where p = q = 2 (mod 3).
    For e=3, the basic correctness dondition m = m^ed (mod pq) 
    holds. Decryption is rendered efficient via the Chinese 
    Remainder Theorem. 

    To build, make sure you have the GMP package. It's called 
    `libgmp3-dev` on Debian-based systems. 
    
    TODO 
      
      - Format checking in rsa_read_{private,prviate}()
      - rsa_{enc,dec}(): power function reveals timing information.
        GMP provides a version that is supposedly resistent to timing
        attacks. 


cipher/ 

  chacha.{h,c}

    The ChaCha streamcipher, invented by Daniel Bernstein in 2008. 
    (http://cr.yp.to/chacha.html) This is the ChaCha16 variant, 
    meaning it performs 16 quarter-round mixes. 
    
    TODO
      
      - Fix endianness and test it. 
      - chacha_streamcipher(). 
      - Is there a rotate instruction on x86? Use architecture-
        specific QR function if possible. 
      - Look into SIMD instructions on x86. 

hash/ 

  sha1.{h,c} (not my own)

    Reference implementation of the SHA-1 cryptographic hash function 
    provided freely in the RFC3174 text.  
