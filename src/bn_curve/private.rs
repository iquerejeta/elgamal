#![allow(non_snake_case)]
use clear_on_drop::clear::Clear;
use core::ops::Mul;
use rand_core::{CryptoRng, OsRng, RngCore};
use rand::{Rng, thread_rng};

use bincode::rustc_serialize::{encode, decode};
use bincode::SizeLimit::Infinite;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use bincode;

use bn::{Fr, G1, Group};

use crate::bn_curve::ciphertext::*;
use crate::bn_curve::public::*;

/// Secret key is a scalar forming the public Key.
#[derive(Clone)]
pub struct SecretKey(Fr);

// todo: this is important
// /// Overwrite secret key material with null bytes.
// impl Drop for SecretKey {
//     fn drop(&mut self) {
//         self.0.clear();
//     }
// }

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl SecretKey {
    /// Create new SecretKey
    pub fn new<T: Rng>(csprng: &mut T) -> Self {
        let mut bytes = [0u8; 64];
        csprng.fill_bytes(&mut bytes);
        SecretKey(Fr::interpret(&bytes))
    }

    /// Get scalar value
    pub fn get_scalar(&self) -> Fr {
        self.0
    }

    /// Decrypt ciphertexts
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> G1 {
        let (point1, point2) = ciphertext.get_points();
        point2 - point1 * self.0
    }

    // /// Convert to bytes
    // pub fn to_bytes(&self) -> [u8; 32] {
    //     self.0.to_bytes()
    // }

    /// Prove correct decryption without depending on the zkp toolkit, which
    /// uses Merlin for Transcripts. The latter is hard to mimic in solidity
    /// smart contracts. To this end, we define this alternative proof of correct
    /// decryption which allows us to proceed with the verification in solidity.
    /// This function should only be used in the latter case. If the verification is
    /// performed in rust, `prove_correct_decryption` function should be used.
    pub fn prove_correct_decryption_no_Merlin(
        &self,
        ciphertext: &Ciphertext,
        message: &G1,
    ) -> ((G1, G1), Fr) {
        let mut rng = thread_rng();
        let pk = PublicKey::from(self);
        let announcement_random = Fr::random(&mut rng);
        let announcement_base_G = G1::one() * announcement_random;
        let announcement_base_ctxtp0 = ciphertext.points.0 * announcement_random;

        let hash = Sha512::new()
                .chain(encode(message, Infinite).unwrap())
                .chain(encode(&ciphertext.points.0, Infinite).unwrap())
                .chain(encode(&ciphertext.points.1, Infinite).unwrap())
                .chain(encode(&announcement_base_G, Infinite).unwrap())
                .chain(encode(&announcement_base_ctxtp0, Infinite).unwrap())
                .chain(encode(&G1::one(), Infinite).unwrap())
                .chain(encode(&pk.get_point(), Infinite).unwrap());

        let mut output = [0u8; 64];
        output.copy_from_slice(hash.result().as_slice());
        let challenge = Fr::interpret(&output);

        let response = announcement_random + challenge * self.get_scalar();
        (
            (
                announcement_base_G,
                announcement_base_ctxtp0,
            ),
            response,
        )
    }
}

impl From<Fr> for SecretKey {
    fn from(secret: Fr) -> SecretKey {
        SecretKey(secret)
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    /// Given a secret key, compute its corresponding Public key
    fn from(secret: &'a SecretKey) -> PublicKey {
        PublicKey::from(G1::one() * secret.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_decryption() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = G1::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);

        let decryption = sk.decrypt(&ciphertext);

        assert!(plaintext == decryption)
    }
    #[test]
    fn prove_correct_decryption_no_Merlin() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = G1::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);

        let decryption = sk.decrypt(&ciphertext);
        let proof = sk.prove_correct_decryption_no_Merlin(&ciphertext, &decryption);

        assert!(pk.verify_correct_decryption_no_Merlin(proof, ciphertext, decryption));
    }

    // #[test]
    // fn prove_false_decryption_no_Merlin() {
    //     let mut csprng = OsRng;
    //     let sk = SecretKey::new(&mut csprng);
    //     let pk = PublicKey::from(&sk);
    //
    //     let plaintext = RistrettoPoint::random(&mut csprng);
    //     let ciphertext = pk.encrypt(&plaintext);
    //
    //     let fake_decryption = RistrettoPoint::random(&mut csprng);
    //     let proof = sk.prove_correct_decryption_no_Merlin(&ciphertext, &fake_decryption);
    //
    //     assert!(!pk.verify_correct_decryption_no_Merlin(&proof, &ciphertext, &fake_decryption));
    // }
    //
    // #[test]
    // fn test_serde_secretkey() {
    //     use bincode;
    //
    //     let mut csprng = OsRng;
    //     let sk = SecretKey::new(&mut csprng);
    //
    //     let encoded = bincode::serialize(&sk).unwrap();
    //     let decoded: SecretKey = bincode::deserialize(&encoded).unwrap();
    //     assert_eq!(sk, decoded);
    // }
}
