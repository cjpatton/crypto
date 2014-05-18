oaep-rsa.c

  Generate RSA keys and encrypt / decrypt files under OAEP-RSA, 
  using the SHA-1 cryptographic hash funciton. 


oaep.{h,c}

  Implementation of the optimal asymmetric encryption padding 
  scheme by Bellare and Rogaway (RFC3447).
  
  TODO 
  
    - Optimize.
    - Push all integrity checks up stream to avoid redundencies.
    - Precompute lMsgBuff, store in oaep_context_t. 
    - `lMsgBuff % lSeed == 0` is a requirement. When producing
      the mask, we do `++(char)seed[0]` for each chunk. Obviously 
      the number of chunks is limited to 256. Maybe this should be
      stated explicitly. 


rsa.{h,c}
  
  Implementation of textbook RSA. It uses the GMP library 
  (http://gmplib.org) for arithmetic over arbitrary precision 
  integers. The keys are generated from n-bit primes p and q,
  where p = q = 2 (mod 3). For e=3, the basic correctness dondition
  m = m^ed (mod pq) holds. Decryption is rendered efficient via the
  Chinese Remainder Theorem. 

  To build, make sure you have the GMP package. It's called 
  `libgmp3-dev` on Debian-based systems. 
  
  TODO 
    
    - Format checking in rsa_read_{private,prviate}()
    - rsa_{enc,dec}(): power function reveals timing information. 

dh.{h,c} TODO

  Implementation Diffie-Hellman authenticated key exchange (AKE). 

chacha.{h,c} TODO 

  Implementation of the ChaCha streamcipher from Daniel Bernstein. 
  (http://cr.yp.to/chacha.html)

sha1.{h,c} (not my own)

  Reference implementation of the SHA-1 cryptographic hash function 
  provided in RFC3174.  
