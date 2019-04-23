# Private contact discovery

Signal [uses SGX](https://signal.org/blog/private-contact-discovery/) to solve
the following problem: A new Signal user is registered and wants to know which
of his or her contacts also use the app. Devise a protocol by which the server
learns *none* of the user's contacts that are *not* Signal users, and the client
learns *none* of the set of Signal users that are *not* one of its contacts.
Users are identified by their phone numbers, so the client can attempt to
enumerate the set of users by trying different phone numbers. We don't intend to
defeat this kind of attack.

This is an instance of the private set intersection (PSI) problem. The question
we ask here is how might we utilize SGX to make such protocols more efficient?
Is GG/OT+SGX the right solution? One reason to consider circuit-based protocols
for PSI is that it makes it easier to extend the protocol to computing functions
of the intersection: See [PSWW'18](https://eprint.iacr.org/2018/120.pdf).
However, this approach does not solve the **bandwidth problem**.

## `tex/contact1`
This is a pairings-based approach. Cryptosystems based on pairings usually
implicate a *trusted third party* in the protocol, such as Boneh and
Franklin's scheme for [identity-based
encryption](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf). Similarly, our
protocol requires the use of a long-term secret key by the server. But knowing
this key can violate security. Thus, we leverage SGX for operations involving
the secret, as well as provisioning secrets to clients.

## `tex/contact0`
This is the first try. It has some security flaws addressed by `contact1`.
