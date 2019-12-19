This module contains notes on how ElGamal works. Given that we implement the scheme using a group defined over an 
Elliptic Curve, we use additive notation. 

ElGamal Cryptosystem
====================
The ElGamal cryptosystem is defined by three algorithms, 
\\(\texttt{KeyGen}, \texttt{Encrypt} \text{ and }\texttt{Decrypt}\\). The key generation algorithm 
\\(\textt{KeyGen}(G, p)\\) outputs a public-private key-pair \\(pk = sk \cdot G\\) for \\(sk \leftarrow\mathbb{Z}_p\\). 
The encryption function \\(\texttt{Encrypt}(pk, M)\\) takes as input a public key \\(pk\\) and a message \\(M \in G\\) 
and returns a ciphertext \\(C = (C_1, C_2) = (r G, M + r pk)\\) for \\(r \leftarrow \mathbb{Z}_p\\). The 
decryption algorithm \\(\texttt{Decrypt}(sk, C)\\) returns the message \\(M = C_2 - sk C_1\\).

Note that the plaintext space is the group \\(G\\), and hence the plaintexts must be encoded as elliptic curve points. 
To exploit the additive homomorphic property of ElGamal encryption over the integers modulo \\(p\\), we encode the 
values as

\\[\texttt{Encode}(x) = x G \text{ for } x\in \mathbb{Z}_p \\]  

We make abuse of notation to denote encryption of \\(x\in\mathbb{Z}_p\\), and write 
\\(\texttt{Encrypt}(x) = \texttt{Encrypt}(\texttt{Encode}(x))\\). Using this encoding, we can exploit the additive
homomorphic property when encrypting two plaintexts, \\(m_1, m_2 \in\mathbb{Z}_p\\):

\\[ 
\begin{align}
    \texttt{Encrypt}(pk, m_1)\oplus\texttt{Encrypt}(pk, m_2)& = (r_1 G, m_1 G + r_1 pk)\oplus (r_1 G, m_2 G + r_1 pk) \\\\
    & = ((r_1 + r_2) G, (m_1 + m_2) G + (r_1 + r_2) pk) \\\\
    & = \texttt{Encrypt}(pk, m_1 + m_2) 
\end{align}    
\\]

Note, however, that when encoding integers using this encoding and exploiting the additive homomorphic property, the 
decryption procedure requires the discrete logarithm calculation to extract the message: 

\\[
\texttt{Decrypt}(sk, (r_1 G, m_1 G + r_1 pk)) = m_1 G
\\]

Hence, in order to successfully use this encryption scheme as defined above, the plaintext space needs to be small, 
e.g. the number of votes received by a candidate in an election or wallet balances in a crypto currency. 

**Important:** The current state of the crate does not support encryption/decryption of byte arrays. 