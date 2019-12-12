# ElGamal

Efficient pure-Rust library for the [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption) additive homomorphic
encryption scheme using the [Ristretto](https://ristretto.group/) primer order group using the ristretto255 
implementation in [`curve25519-dalek`]. 

This library provides implementations of: 
* Additively Homomorphic ElGamal Encryption and decryption.
* Zero Knowledge Proofs using the toolkit for proof generation [`zkp`] supporting proof generation and verification
 of correct encryption, correct decryption and knowledge of private key.
* [EdDSA](https://en.wikipedia.org/wiki/EdDSA) generation and verification.

## Encryption Scheme
Let **G** denote the Ristretto group with primer order, **p**, whose generator is denoted by **g**. We write **Zp** for 
the integers modulo **p**. We write a<-- A to denote that a is chosen uniformly at random from the set A. 

ElGamal encryption scheme is given by the algorithms `key_generation`, `encrypt` and `decrypt`. The key generation 
algorithm  

**Important**: while we have followed recommendations regarding the scheme itself, this library should currently be seen
 as an experimental implementation. In particular, no particular efforts have so far been made to harden it against
 non-cryptographic attacks, including side-channel attacks.
