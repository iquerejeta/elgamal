# ElGamal

Efficient pure-Rust library for the [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption) additive homomorphic
encryption scheme using the Ristretto primer order group over Curve25519. Library also supports signature following
[EdDSA](https://en.wikipedia.org/wiki/EdDSA).

**Important**: while we have followed recommendations regarding the scheme itself, this library should currently be seen
 as an experimental implementation. In particular, no particular efforts have so far been made to harden it against
 non-cryptographic attacks, including side-channel attacks.
