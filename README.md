[![crates.io](https://img.shields.io/crates/v/elgamal-ristretto.svg)](https://crates.io/crates/elgamal-ristretto)

# ElGamal

Efficient pure-Rust library for the [ElGamal][elgamal] additive homomorphic
encryption scheme using the [Ristretto][ristretto] primer order group using the ristretto255 
implementation in [`curve25519-dalek`][curve25519-dalek]. 

This library provides implementations of: 
* Additively Homomorphic ElGamal Encryption and decryption.
* Zero Knowledge Proofs using the toolkit for proof generation [`zkp`][zkp] supporting proof generation and verification
 of correct encryption, correct decryption and knowledge of private key.
* [EdDSA](https://en.wikipedia.org/wiki/EdDSA) generation and verification.

**Important**: while we have followed recommendations regarding the scheme itself, this library should currently be seen
 as an experimental implementation. In particular, no particular efforts have so far been made to harden it against
 non-cryptographic attacks, including side-channel attacks.
 
 [elgamal]: https://en.wikipedia.org/wiki/ElGamal_encryption
 [ristretto]: https://ristretto.group/
 [zkp]: https://github.com/dalek-cryptography/zkp
 [curve25519-dalek]: https://github.com/dalek-cryptography/curve25519-dalek
