This module contains notes on the three zero knowledge proofs (ZKP) we decided to include in the crate to offer a higher
functionality when using the ElGamal Cryptosystem. These proofs are a proof of correct 
decryption, proof of correct randomization and a proof of knowledge of a secret key. 

We use standard [Zero Knowledge Proofs of Knowledge][standardProofs] to prove the different operations in the ElGamal
cryptosystem and use the [zkp][zkp] compiler to generate them. It uses the Fiat-Shamir heuristic to convert them 
into non-interactive proofs of knowledge. 

The compiler follows the Camenisch-Standler notation to denote proofs and write:

\\[
\texttt{ZKP-DL}\{(x), (H), (G): H = (x * G)\}
\\] 

to denote the non-interactive proof of knowledge that the prover knows the discrete logarithm base \\(G\\) of
\\(H\\), \\(x\\). We use two different tastes of ZKPs, the aforementioned proof of discrete logarithm, and a proof 
of equality of discrete log: 
\\[
\textttt{ZKP-DLEQ}\{(x), (A, B, H), (G): H = (x * G) \wedge A = (x * B) \}
\\]


Proof of correct Decryption
===========================

Assume that the key-owner of the public key used to encrypt a plaintext, wants to decrypt the ciphertext and proof 
correctness. Obviously, the interest here is to prove correctness without disclosing any information about the 
private key itself. For this, we use the following Zero Knowledge Proof. 

Recall that decrypt functions performs the following, \\(\texttt{Decrypt}(sk, C) = C_2 - sk \cdot C_1 = M\\). Moreover, 
note that \\(C = (C_1, C_2) = (r G, M + r Q)\\) with \\(Q = sk \cdot G\\). Then, in order to prove that \\(M\\) is 
indeed the correct decryption of \\(C\\), the prover needs to compute the following proof: 
\\[
\textttt{ZKP-DLEQ}\{(sk), (C_1, (C_2 - M), Q), (G): Q = sk \cdot G \wedge (C_2 - M) = sk \cdot C_1\}
\\]


Proof of knowledge of secret key
================================

Given a public key, the owner wants to prove that it indeed is the owner of the key. To this end, the owner generates
a proof that it knows the discrete log base \\(G\\) of \\(Q\\), i.e.: 
\\[
\texttt{ZKP-DL}\{(sk), (Q), (G): Q = sk \cdot G\} 
\\]


[standardProofs]:https://dl.acm.org/citation.cfm?id=22178
[zkp]: https://github.com/dalek-cryptography/zkp