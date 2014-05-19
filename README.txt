This is a collection of cryptographic algorithms and tools
written in order to deepen my own understanding. They aren't
intended for use in the wild ( ... yet ;p ). All except the 
SHA1 implementation (see below) are my own work.   

oaep-rsa.c

  Generate RSA keys and encrypt / decrypt files under OAEP-RSA, 
  using the SHA-1 cryptographic hash funciton. 


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


dh.{h,c} TODO

  Diffie-Hellman authenticated key exchange (AKE). 


chacha.{h,c}

  The ChaCha streamcipher, invented by Daniel Bernstein in 2008. 
  (http://cr.yp.to/chacha.html) This is the ChaCha16 variant, 
  meaning it performs 16 quarter-round mixes. 
  
  TODO
    
    - chacha_streamcipher(). 
    - Is there a rotate instruction on x86? Use architecture-
      specific QR function if possible. 
    - Look into SIMD instructions on x86. 


sha1.{h,c} (not my own)

  Reference implementation of the SHA-1 cryptographic hash function 
  provided freely in the RFC3174 text.  
