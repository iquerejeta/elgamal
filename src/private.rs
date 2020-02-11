use clear_on_drop::clear::Clear;
use core::ops::Mul;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use zkp::{CompactProof, Transcript};

use crate::ciphertext::*;
use crate::public::*;

/// Secret key is a scalar forming the public Key.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretKey(Scalar);

/// Overwrite secret key material with null bytes.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl SecretKey {
    /// Create new SecretKey
    pub fn new<T: RngCore + CryptoRng>(csprng: &mut T) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        SecretKey(clamp_scalar(bytes).reduce())
    }

    /// Get scalar value
    pub fn get_scalar(&self) -> Scalar {
        self.0
    }

    /// Decrypt ciphertexts
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> RistrettoPoint {
        let (point1, point2) = ciphertext.get_points();
        point2 - point1 * self.0
    }

    /// Sign a message using EdDSA algorithm.
    pub fn sign(&self, message: &RistrettoPoint) -> (Scalar, RistrettoPoint) {
        let pk = PublicKey::from(self);
        let random_signature = Scalar::from_hash(
            Sha512::new()
                .chain(message.compress().to_bytes())
                .chain(self.0.to_bytes()),
        );
        let signature_point = &random_signature * &RISTRETTO_BASEPOINT_POINT;

        let signature_scalar = random_signature
            + Scalar::from_hash(
                Sha512::new()
                    .chain(signature_point.compress().to_bytes())
                    .chain(pk.to_bytes())
                    .chain(message.compress().to_bytes()),
            ) * self.0;

        (signature_scalar, signature_point)
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Proof Knowledge of secret key
    pub fn prove_knowledge(&self) -> CompactProof {
        let pk = PublicKey::from(self);
        let mut transcript = Transcript::new(b"ProveKnowledgeSK");
        let (proof, _) = dl_knowledge::prove_compact(
            &mut transcript,
            dl_knowledge::ProveAssignments {
                x: &self.0,
                A: &pk.get_point(),
                G: &RISTRETTO_BASEPOINT_POINT,
            },
        );
        proof
    }

    /// Prove correct decryption
    /// (x), (A, B, H), (G) : A = (x * B), H = (x * G)
    pub fn prove_correct_decryption(
        &self,
        ciphertext: &Ciphertext,
        message: &RistrettoPoint,
    ) -> CompactProof {
        let pk = PublicKey::from(self);
        let mut transcript = Transcript::new(b"ProveCorrectDecryption");
        let (proof, _) = dleq::prove_compact(
            &mut transcript,
            dleq::ProveAssignments {
                x: &self.0,
                A: &(ciphertext.points.1 - message),
                B: &ciphertext.points.0,
                H: &pk.get_point(),
                G: &RISTRETTO_BASEPOINT_POINT,
            },
        );
        proof
    }
}

// todo: why do we have this?
impl<'a, 'b> Mul<&'b Scalar> for &'a SecretKey {
    type Output = Scalar;
    fn mul(self, other: &'b Scalar) -> Scalar {
        &self.0 * other
    }
}

impl From<Scalar> for SecretKey {
    fn from(secret: Scalar) -> SecretKey {
        SecretKey(secret)
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    /// Given a secret key, compute its corresponding Public key
    fn from(secret: &'a SecretKey) -> PublicKey {
        PublicKey::from(&RISTRETTO_BASEPOINT_POINT * &secret.0)
    }
}

define_mul_variants!(LHS = SecretKey, RHS = Scalar, Output = Scalar);

// "Decode" a scalar from a 32-byte array. Read more regarding this key clamping.
fn clamp_scalar(scalar: [u8; 32]) -> Scalar {
    let mut s: [u8; 32] = scalar.clone();
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    Scalar::from_bits(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    #[test]
    fn create_and_verify_sk_knowledge() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let proof = sk.prove_knowledge();
        assert!(pk.verify_proof_knowledge(&proof));
    }

    #[test]
    fn create_and_verify_fake_sk_knowledge() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let fake_pk = PublicKey::from(RistrettoPoint::random(&mut csprng));

        let proof = sk.prove_knowledge();
        assert!(!fake_pk.verify_proof_knowledge(&proof));
    }

    #[test]
    fn prove_correct_decryption() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);

        let decryption = sk.decrypt(&ciphertext);
        let proof = sk.prove_correct_decryption(&ciphertext, &decryption);

        assert!(pk.verify_correct_decryption(&proof, &ciphertext, &decryption));
    }

    #[test]
    fn prove_false_decryption() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);

        let fake_decryption = RistrettoPoint::random(&mut csprng);
        let proof = sk.prove_correct_decryption(&ciphertext, &fake_decryption);

        assert!(!pk.verify_correct_decryption(&proof, &ciphertext, &fake_decryption));
    }

    #[test]
    fn test_signature() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let msg = RistrettoPoint::random(&mut csprng);
        let signature = sk.sign(&msg);
        assert!(pk.verify_signature(&msg, signature));
    }

    #[test]
    fn test_signature_failure() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let msg = RistrettoPoint::random(&mut csprng);
        let msg_unsigned = RistrettoPoint::random(&mut csprng);
        let signature = sk.sign(&msg);

        assert!(!pk.verify_signature(&msg_unsigned, signature));
    }

    #[test]
    fn test_serde_secretkey() {
        use bincode;

        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);

        let encoded = bincode::serialize(&sk).unwrap();
        let decoded: SecretKey = bincode::deserialize(&encoded).unwrap();
        assert_eq!(sk, decoded);
    }
}
