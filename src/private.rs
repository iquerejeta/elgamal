use clear_on_drop::clear::Clear;
use core::ops::{Mul, };
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, };
use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{RngCore, CryptoRng, };
use sha2::{Digest, Sha512};

use zkp::{Transcript, CompactProof, };

use crate::ciphertext::*;
use crate::public::*;

/// Secret key is a scalar forming the public Key.
#[derive(Clone, Debug)]
pub struct SecretKey(Scalar);

/// Overwrite secret key material with null bytes.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl SecretKey {
    /// Create new SecretKey
    pub fn new<T: RngCore + CryptoRng>(csprng: &mut T) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        SecretKey(clamp_scalar(bytes))
    }

    /// Decrypt ciphertexts
    pub fn decrypt(&self, ciphertext: Ciphertext) -> RistrettoPoint {
        let (point1, point2) = ciphertext.get_points();
        point2 - point1 * self.0
    }

    /// Sign a message using EdDSA algorithm.
    pub fn sign(&self, message: RistrettoPoint) -> (Scalar, RistrettoPoint) {
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

    /// Proof Knowledge of secret key
    pub fn prove_knowledge(&self) -> CompactProof {
        let base = RISTRETTO_BASEPOINT_POINT;
        let pk = PublicKey::from(self);

        let mut transcript = Transcript::new(b"ProveKnowledgeSK");
        let (proof, _) = dl_knowledge::prove_compact(
            &mut transcript,
            dl_knowledge::ProveAssignments {
                x: &self.0,
                A: &pk.get_point(),
                G: &base,
            }
        );
        proof
    }

    /// Prove correct decryption
    /// (x), (A, B, H), (G) : A = (x * B), H = (x * G)
    pub fn prove_correct_decryption(&self, ciphertext: Ciphertext, message: RistrettoPoint) -> CompactProof {
        let base = RISTRETTO_BASEPOINT_POINT;
        let pk = PublicKey::from(self);

        let mut transcript = Transcript::new(b"ProveCorrectDecryption");
        let (proof, _) = dleq::prove_compact(
            &mut transcript,
            dleq::ProveAssignments {
                x: &self.0,
                A: &(ciphertext.points.1 - message),
                B: &ciphertext.points.0,
                H: &pk.get_point(),
                G: &base,
            }
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