# ElGamal

Efficient pure-Rust library for the [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption) additive homomorphic
encryption scheme using the [Ristretto](https://ristretto.group/) primer order group using the ristretto255 
implementation in [`curve25519-dalek`][curve25519_dalek]. 

This library provides implementations of: 
* Additively Homomorphic ElGamal Encryption and decryption.
* Zero Knowledge Proofs using the toolkit for proof generation [`zkp`][zkp] supporting proof generation and verification
 of correct encryption, correct decryption and knowledge of private key.
* [EdDSA](https://en.wikipedia.org/wiki/EdDSA) generation and verification.

**Important**: while we have followed recommendations regarding the scheme itself, this library should currently be seen
 as an experimental implementation. In particular, no particular efforts have so far been made to harden it against
 non-cryptographic attacks, including side-channel attacks.
