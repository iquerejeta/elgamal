#[macro_use]
pub mod macros;

use clear_on_drop::clear::Clear;
use core::ops::{Add, Div, Mul, Sub};
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_COMPRESSED};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{RngCore, CryptoRng, OsRng, };
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

#[macro_use]
extern crate zkp;
use zkp::{Transcript, CompactProof, };

define_proof! {dl_knowledge, "DLKnowledge Proof", (x), (A), (G) : A = (x * G)}
define_proof! {dleq, "DLEQ Proof", (x), (A, B, H), (G) : A = (x * B), H = (x * G)}

/// The `PublicKey` struct represents an ElGamal public key.
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct PublicKey(RistrettoPoint);

impl PublicKey {
    /// Encrypts a message in the Ristretto group. It has the additive homomorphic property,
    /// allowing addition (and subtraction) by another ciphertext and multiplication (and division)
    /// by scalars.
    ///
    /// #Example
    /// ```
    /// extern crate rand;
    /// extern crate curve25519_dalek;
    /// extern crate elgamal_ristretto;
    /// use rand_core::OsRng;
    /// use elgamal_ristretto::{PublicKey, SecretKey};
    /// use curve25519_dalek::ristretto::{RistrettoPoint, };
    /// use curve25519_dalek::scalar::{Scalar, };
    ///
    /// # fn main() {
    ///        let mut csprng = OsRng;
    ///        // Generate key pair
    ///        let sk = SecretKey::new(&mut csprng);
    ///        let pk = PublicKey::from(&sk);
    ///
    ///        // Generate random messages
    ///        let ptxt1 = RistrettoPoint::random(&mut csprng);
    ///        let ptxt2 = RistrettoPoint::random(&mut csprng);
    ///
    ///        // Encrypt messages
    ///        let ctxt1 = pk.encrypt(ptxt1);
    ///        let ctxt2 = pk.encrypt(ptxt2);
    ///
    ///        // Add ciphertexts and check that addition is maintained in the plaintexts
    ///        let encrypted_addition = ctxt1 + ctxt2;
    ///        let decrypted_addition = sk.decrypt(encrypted_addition);
    ///
    ///        assert_eq!(ptxt1 + ptxt2, decrypted_addition);
    ///
    ///        // Multiply by scalar and check that multiplication is maintained in the plaintext
    ///        let scalar_mult = Scalar::random(&mut csprng);
    ///        assert_eq!(sk.decrypt(ctxt1 * scalar_mult), scalar_mult * ptxt1);
    /// # }
    /// ```
    pub fn encrypt(self, message: RistrettoPoint) -> Ciphertext {
        let mut csprng: OsRng = OsRng;
        let mut random: Scalar = Scalar::random(&mut csprng);

        let random_generator = &RISTRETTO_BASEPOINT_POINT * &random;
        let encrypted_plaintext = message + &self.0 * &random;
        random.clear();
        Ciphertext {
            pk: self,
            points: (random_generator, encrypted_plaintext),
        }
    }

    /// Encrypts a message in the Ristretto group and generates a proof of correct encryption
    ///
    /// #Example
    /// ```
    /// extern crate rand;
    /// extern crate curve25519_dalek;
    /// extern crate elgamal_ristretto;
    /// use rand_core::OsRng;
    /// use elgamal_ristretto::{PublicKey, SecretKey};
    /// use curve25519_dalek::ristretto::{RistrettoPoint, };
    ///
    /// # fn main() {
    /// let mut csprng = OsRng;
    ///        let sk = SecretKey::new(&mut csprng);
    ///        let pk = PublicKey::from(&sk);
    ///
    ///        let plaintext = RistrettoPoint::random(&mut csprng);
    ///        // Encrypt plaintext and generate proof
    ///        let (enc_plaintext, proof) = pk.encrypt_and_prove(plaintext);
    ///
    ///        // Verify proof
    ///        assert!(enc_plaintext.verify_correct_encryption(&plaintext, proof));
    /// # }
    /// ```
    pub fn encrypt_and_prove(
        self,
        message: RistrettoPoint,
    ) -> (Ciphertext, CompactProof) {
        let mut csprng: OsRng = OsRng;
        let mut random: Scalar = Scalar::random(&mut csprng);

        let random_generator = &RISTRETTO_BASEPOINT_POINT * &random;
        let encrypted_plaintext = message + &self.0 * &random;

        let mut transcript = Transcript::new(b"CorrectEncryption");
        let (proof, _) = dleq::prove_compact(
            &mut transcript,
            dleq::ProveAssignments {
                x: &random,
                A: &(encrypted_plaintext - message),
                B: &self.get_point(),
                H: &random_generator,
                G: &RISTRETTO_BASEPOINT_POINT,
            }
        );

        // let proof = prove_dlog_knowledge(random, self.get_point(), encrypted_plaintext - message);

        random.clear();
        (Ciphertext {
            pk: self,
            points: (random_generator, encrypted_plaintext),
        },
        proof)
    }

    /// Get the public key as a RistrettoPoint
    pub fn get_point(&self) -> RistrettoPoint {
        self.0
    }

    /// Verify EdDSA signature
    ///
    /// #Example
    /// ```
    /// extern crate rand;
    /// extern crate curve25519_dalek;
    /// extern crate elgamal_ristretto;
    /// use rand_core::OsRng;
    /// use elgamal_ristretto::{PublicKey, SecretKey};
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    ///
    /// # fn main() {
    ///       // Generate key-pair
    ///       let mut csprng = OsRng;
    ///       let sk = SecretKey::new(&mut csprng);
    ///       let pk = PublicKey::from(&sk);
    ///
    ///       // Sign message
    ///       let msg = RistrettoPoint::random(&mut csprng);
    ///       let signature = sk.sign(msg);
    ///       // Verify signature
    ///       assert!(pk.verify_signature(&msg, signature));
    ///
    ///       // Verify signature against incorrect message
    ///       assert!(!pk.verify_signature(&RistrettoPoint::random(&mut csprng), signature))
    /// # }
    /// ```
    pub fn verify_signature(self, message: &RistrettoPoint, signature: (Scalar, RistrettoPoint)) -> bool {
        let verification_hash = Scalar::from_hash(
            Sha512::new()
                .chain(signature.1.compress().to_bytes())
                .chain(self.0.compress().to_bytes())
                .chain(message.compress().to_bytes()),
        );

        let check =
            &signature.0 * &RISTRETTO_BASEPOINT_POINT == signature.1 + verification_hash * self.0;
        check
    }

    /// Verify proof of knowledege of private key related to a public key
    ///
    /// Example
    /// ```
    /// extern crate rand;
    /// extern crate curve25519_dalek;
    /// extern crate elgamal_ristretto;
    /// use rand_core::OsRng;
    /// use elgamal_ristretto::{PublicKey, SecretKey};
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    ///
    /// # fn main() {
    ///       let mut csprng = OsRng;
    ///       let sk = SecretKey::new(&mut csprng);
    ///       let pk = PublicKey::from(&sk);
    ///
    ///       let proof = sk.prove_knowledge();
    ///       assert!(pk.verify_proof_knowledge(proof));
    /// # }
    /// ```
    pub fn verify_proof_knowledge(self, proof: CompactProof) -> bool {
        let mut transcript = Transcript::new(b"ProveKnowledgeSK");
        dl_knowledge::verify_compact(
            &proof,
            &mut transcript,
            dl_knowledge::VerifyAssignments {
                A: &self.0.compress(),
                G: &RISTRETTO_BASEPOINT_COMPRESSED,
            },
        ).is_ok()
    }

    /// Verify correct decryption
    ///
    /// Example
    /// ```
    /// extern crate rand;
    /// extern crate curve25519_dalek;
    /// extern crate elgamal_ristretto;
    /// use rand_core::OsRng;
    /// use elgamal_ristretto::{PublicKey, SecretKey};
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    ///
    /// # fn main() {
    ///    let mut csprng = OsRng;
    ///    let sk = SecretKey::new(&mut csprng);
    ///    let pk = PublicKey::from(&sk);
    ///
    ///    let plaintext = RistrettoPoint::random(&mut csprng);
    ///    let ciphertext = pk.encrypt(plaintext);
    ///
    ///    let decryption = sk.decrypt(ciphertext);
    ///    let proof = sk.prove_correct_decryption(ciphertext, decryption);
    ///
    ///    assert!(pk.verify_correct_decryption(proof, ciphertext, decryption));
    /// # }
    /// ```
    pub fn verify_correct_decryption(self, proof: CompactProof, ciphertext: Ciphertext, plaintext: RistrettoPoint) -> bool {
        let mut transcript = Transcript::new(b"ProveCorrectDecryption");
        dleq::verify_compact(
            &proof,
            &mut transcript,
            dleq::VerifyAssignments {
                A: &(ciphertext.points.1 - plaintext).compress(),
                B: &ciphertext.points.0.compress(),
                H: &self.get_point().compress(),
                G: &RISTRETTO_BASEPOINT_COMPRESSED
            },
        ).is_ok()
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Generate public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> PublicKey {
        PublicKey(CompressedRistretto::from_slice(bytes).decompress().unwrap())
    }
}

impl From<RistrettoPoint> for PublicKey {
    /// Given a secret key, compute its corresponding Public key
    fn from(point: RistrettoPoint) -> PublicKey {
        PublicKey(point)
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    /// Given a secret key, compute its corresponding Public key
    fn from(secret: &'a SecretKey) -> PublicKey {
        PublicKey(&RISTRETTO_BASEPOINT_POINT * &secret.0)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.0 == other.0
    }
}

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
                    .chain(pk.0.compress().to_bytes())
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

define_mul_variants!(LHS = SecretKey, RHS = Scalar, Output = Scalar);

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct Ciphertext {
    pub pk: PublicKey,
    pub points: (RistrettoPoint, RistrettoPoint),
}

impl Ciphertext {
    pub fn get_points(self) -> (RistrettoPoint, RistrettoPoint) {
        return (self.points.0, self.points.1);
    }

    /// Verify proof of correct encryption
    pub fn verify_correct_encryption(
        self,
        message_to_verify: &RistrettoPoint,
        proof: CompactProof
    ) -> bool {
        let mut transcript = Transcript::new(b"CorrectEncryption");
        dleq::verify_compact(
            &proof,
            &mut transcript,
            dleq::VerifyAssignments {
                A: &(self.points.1 - message_to_verify).compress(),
                B: &self.pk.get_point().compress(),
                H: &self.get_points().0.compress(),
                G: &RISTRETTO_BASEPOINT_COMPRESSED,
            },
        ).is_ok()
        // verify_dlog_knowledge_proof(self.pk.get_point().compress(), value.compress(), proof)
    }
}

impl<'a, 'b> Add<&'b Ciphertext> for &'a RistrettoPoint {
    type Output = Ciphertext;

    fn add(self, other: &'b Ciphertext) -> Ciphertext {
        Ciphertext {
            pk: other.pk,
            points: (other.points.0, self + &other.points.1),
        }
    }
}

define_add_variants!(LHS = RistrettoPoint, RHS = Ciphertext, Output = Ciphertext);

impl<'a, 'b> Add<&'b RistrettoPoint> for &'a Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: &'b RistrettoPoint) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (self.points.0, &self.points.1 + other),
        }
    }
}

define_add_variants!(LHS = Ciphertext, RHS = RistrettoPoint, Output = Ciphertext);

impl<'a, 'b> Sub<&'b Ciphertext> for &'a RistrettoPoint {
    type Output = Ciphertext;

    fn sub(self, other: &'b Ciphertext) -> Ciphertext {
        Ciphertext {
            pk: other.pk,
            points: (-other.points.0, self - &other.points.1),
        }
    }
}

define_sub_variants!(LHS = RistrettoPoint, RHS = Ciphertext, Output = Ciphertext);

impl<'a, 'b> Sub<&'b RistrettoPoint> for &'a Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: &'b RistrettoPoint) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (self.points.0, &self.points.1 - other),
        }
    }
}

define_sub_variants!(LHS = Ciphertext, RHS = RistrettoPoint, Output = Ciphertext);

impl<'a, 'b> Add<&'b Ciphertext> for &'a Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: &'b Ciphertext) -> Ciphertext {
        if self.pk != other.pk {
            panic!("Abort! Ciphertexts can only be added if public keys equal");
        }
        Ciphertext {
            pk: self.pk,
            points: (
                &self.points.0 + &other.points.0,
                &self.points.1 + &other.points.1,
            ),
        }
    }
}

define_add_variants!(LHS = Ciphertext, RHS = Ciphertext, Output = Ciphertext);

impl<'a, 'b> Sub<&'b Ciphertext> for &'a Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: &'b Ciphertext) -> Ciphertext {
        if self.pk != other.pk {
            panic!("Abort! Ciphertexts can only be subtracted if public keys equal");
        }
        Ciphertext {
            pk: self.pk,
            points: (
                &self.points.0 - &other.points.0,
                &self.points.1 - &other.points.1,
            ),
        }
    }
}

define_sub_variants!(LHS = Ciphertext, RHS = Ciphertext, Output = Ciphertext);

impl<'a, 'b> Mul<&'b Scalar> for &'a Ciphertext {
    type Output = Ciphertext;

    fn mul(self, other: &'b Scalar) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (&self.points.0 * other, &self.points.1 * other),
        }
    }
}

define_mul_variants!(LHS = Ciphertext, RHS = Scalar, Output = Ciphertext);

impl<'a, 'b> Div<&'b Scalar> for &'a Ciphertext {
    type Output = Ciphertext;

    fn div(self, other: &'b Scalar) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (
                &self.points.0 * &other.invert(),
                &self.points.1 * &other.invert(),
            ),
        }
    }
}

define_div_variants!(LHS = Ciphertext, RHS = Scalar, Output = Ciphertext);

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
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    fn test_encryption() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt = RistrettoPoint::random(&mut csprng);

        let ctxt = pk.encrypt(ptxt);
        assert_eq!(ptxt, sk.decrypt(ctxt));
    }

    #[test]
    fn test_byte_conversion() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let pk_byte = pk.to_bytes();
        let pk_from_bytes = PublicKey::from_bytes(&pk_byte);

        assert_eq!(pk, pk_from_bytes);
    }

    #[test]
    fn test_signature() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let msg = RistrettoPoint::random(&mut csprng);
        let signature = sk.sign(msg);
        assert!(pk.verify_signature(&msg, signature));
    }

    #[test]
    fn test_signature_failure() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let msg = RistrettoPoint::random(&mut csprng);
        let msg_unsigned = RistrettoPoint::random(&mut csprng);
        let signature = sk.sign(msg);

        assert!(!pk.verify_signature(&msg_unsigned, signature));
    }

    #[test]
    fn test_homomorphic_addition() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt1 = RistrettoPoint::random(&mut csprng);
        let ptxt2 = RistrettoPoint::random(&mut csprng);

        let ctxt1 = pk.encrypt(ptxt1);
        let ctxt2 = pk.encrypt(ptxt2);

        let encrypted_addition = ctxt1 + ctxt2;
        let decrypted_addition = sk.decrypt(encrypted_addition);

        assert_eq!(ptxt1 + ptxt2, decrypted_addition);
    }

    #[test]
    fn test_homomorphic_subtraction() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt1 = RistrettoPoint::random(&mut csprng);
        let ptxt2 = RistrettoPoint::random(&mut csprng);

        let ctxt1 = pk.encrypt(ptxt1);
        let ctxt2 = pk.encrypt(ptxt2);

        let encrypted_addition = ctxt1 - ctxt2;
        let decrypted_addition = sk.decrypt(encrypted_addition);

        assert_eq!(ptxt1 - ptxt2, decrypted_addition);
    }

    #[test]
    fn test_multiplication_by_scalar() {
        // generates public private pair
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let pltxt: RistrettoPoint = RistrettoPoint::random(&mut csprng);
        let enc_pltxt = pk.encrypt(pltxt);

        let mult_factor: Scalar = Scalar::random(&mut csprng);
        let mult_pltxt = pltxt * mult_factor;
        let mult_ctxt = enc_pltxt * mult_factor;
        let mult_dec_pltxt = sk.decrypt(mult_ctxt);

        assert_eq!(mult_dec_pltxt, mult_pltxt);
    }

    #[test]
    fn test_division_by_scalar() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let div_factor: Scalar = Scalar::random(&mut csprng);
        let pltxt: RistrettoPoint = div_factor * RISTRETTO_BASEPOINT_POINT;
        let enc_pltxt = pk.encrypt(pltxt);

        let div_ctxt = enc_pltxt / div_factor;
        let div_dec_pltxt = sk.decrypt(div_ctxt);

        assert_eq!(div_dec_pltxt, RISTRETTO_BASEPOINT_POINT);
    }

    #[test]
    fn test_serde_pubkey() {
        use bincode;

        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let encoded = bincode::serialize(&pk).unwrap();
        let decoded: PublicKey = bincode::deserialize(&encoded).unwrap();

        assert_eq!(pk, decoded);
    }

    #[test]
    fn test_serde_ciphertext() {
        use bincode;

        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext: RistrettoPoint = RistrettoPoint::random(&mut csprng);
        let enc_plaintext = pk.encrypt(plaintext);

        let encoded = bincode::serialize(&enc_plaintext).unwrap();
        let decoded: Ciphertext = bincode::deserialize(&encoded).unwrap();

        assert_eq!(enc_plaintext.pk, decoded.pk);
        assert_eq!(enc_plaintext.points, decoded.points);
    }

    #[test]
    fn create_and_verify_sk_knowledge() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let proof = sk.prove_knowledge();
        assert!(pk.verify_proof_knowledge(proof));
    }

    #[test]
    fn create_and_verify_fake_sk_knowledge() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let fake_pk = PublicKey::from(RistrettoPoint::random(&mut csprng));

        let proof = sk.prove_knowledge();
        assert!(!fake_pk.verify_proof_knowledge(proof));
    }

    #[test]
    fn prove_and_verify_correct_encryption() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let (enc_plaintext, proof) = pk.encrypt_and_prove(plaintext);

        assert!(enc_plaintext.verify_correct_encryption(&plaintext, proof));
    }

    #[test]
    fn prove_and_verify_incorrect_encryption() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let random_plaintext = RistrettoPoint::random(&mut csprng);
        let (enc_plaintext, proof) = pk.encrypt_and_prove(plaintext);

        assert!(!enc_plaintext.verify_correct_encryption(&random_plaintext, proof));
    }

    #[test]
    fn prove_correct_decryption() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let ciphertext = pk.encrypt(plaintext);

        let decryption = sk.decrypt(ciphertext);
        let proof = sk.prove_correct_decryption(ciphertext, decryption);

        assert!(pk.verify_correct_decryption(proof, ciphertext, decryption));
    }

    #[test]
    fn prove_false_decryption() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let ciphertext = pk.encrypt(plaintext);

        let fake_decryption = RistrettoPoint::random(&mut csprng);
        let proof = sk.prove_correct_decryption(ciphertext, fake_decryption);

        assert!(!pk.verify_correct_decryption(proof, ciphertext, fake_decryption));
    }

    #[test]
    fn test_add_of_ciphertext_and_plaintext() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let ciphertext = pk.encrypt(plaintext);
        let plaintext2 = RistrettoPoint::random(&mut csprng);

        assert!(sk.decrypt(plaintext2 + ciphertext) == plaintext + plaintext2);
        assert!(sk.decrypt(ciphertext + plaintext2) == plaintext + plaintext2);
    }

    #[test]
    fn test_sub_of_ciphertext_and_plaintext() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let ciphertext = pk.encrypt(plaintext);
        let plaintext2 = RistrettoPoint::random(&mut csprng);

        assert!(sk.decrypt(plaintext2 - ciphertext) == plaintext2 - plaintext);
        assert!(sk.decrypt(ciphertext - plaintext2) == plaintext - plaintext2);
    }
}
