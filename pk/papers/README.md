Papers
------

**barak2005model**

  - First formal model for PRNG with inputs.
    - Resilience: outputs look random w/o knowledge of state
    - Forward security: prior outputs look random after state exposure.
    - Backward security: future outputs look random after exposure and refresh.
    - Additional goal: the state should not leak anything about the inputs.
      - I'm not sure this captures anything realistic.

**dodis2013security**

  - Extends the model of barak2005model.
    - Robust: strengthens forward+backward security.
  - Attacks on /dev/[u]random.
  - Provides a nice survey of attacks and models.

**shrimpton2015provable**

  - Extends the model of dodis2013security.
  - Analysis of ISK-RNG, the "Intel Secure Key" RNG.

**hoang2016selective**

  - Unifies hedged PKE with selective-opening attacks on PKE:
    "Hedged PKE and nonce-based PKE are incomparable and are useful in different
     scenarios, and part of our contribution is to unify them into a single
     primitive."

The SOA setting is technically very diffrerent than ours. The idea is that a
bunch of clients encrypt messages (that may be jointly distributed) under a
public key and with independent coins. Suppose the message and coins of some
clients are exposed to the adversary. How does this effect the security of the
remaining messages? Check out [9].
