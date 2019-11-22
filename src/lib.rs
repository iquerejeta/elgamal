#[macro_use]
pub mod macros;

use clear_on_drop::clear::Clear;
use core::ops::{Add, Div, Mul, Sub};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

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
    /// use rand::rngs::OsRng;
    /// use elgamal_ristretto::{PublicKey, SecretKey};
    /// use curve25519_dalek::ristretto::{RistrettoPoint, };
    /// use curve25519_dalek::scalar::{Scalar, };
    ///
    /// # fn main() {
    ///        let mut csprng = OsRng::new().unwrap();
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
        let mut csprng: OsRng = OsRng::new().unwrap();
        let mut random: Scalar = Scalar::random(&mut csprng);

        let random_generator = &RISTRETTO_BASEPOINT_TABLE * &random;
        let encrypted_plaintext = message + &self.0 * &random;
        random.clear();
        Ciphertext {
            pk: self,
            points: (random_generator, encrypted_plaintext),
        }
    }

    /// Encrypts a message in the Ristretto group giving the randomization as
    /// input. This is an unsafe function. It should only be used when the randomization is needed
    /// for another purpose, such as generating a proof of correct encryption, or encrypting another
    /// ciphertext with the same randomisation.
    pub unsafe fn encrypt_dirty(
        self,
        message: RistrettoPoint,
        random_encryption: Scalar,
    ) -> Ciphertext {
        let random_generator = &RISTRETTO_BASEPOINT_TABLE * &random_encryption;
        let encrypted_plaintext = message + &self.0 * &random_encryption;
        Ciphertext {
            pk: self,
            points: (random_generator, encrypted_plaintext),
        }
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
    /// use rand::rngs::OsRng;
    /// use elgamal_ristretto::{PublicKey, SecretKey};
    /// use curve25519_dalek::ristretto::{RistrettoPoint, };
    ///
    /// # fn main() {
    ///       // Generate key-pair
    ///       let mut csprng = OsRng::new().unwrap();
    ///       let sk = SecretKey::new(&mut csprng);
    ///       let pk = PublicKey::from(&sk);
    ///
    ///       // Sign message
    ///       let msg = RistrettoPoint::random(&mut csprng);
    ///       let signature = sk.sign(msg);
    ///       // Verify signature
    ///       assert!(pk.verify(&msg, signature));
    ///
    ///       // Verify signature against incorrect message
    ///       assert!(!pk.verify(&RistrettoPoint::random(&mut csprng), signature))
    /// # }
    /// ```
    pub fn verify(self, message: &RistrettoPoint, signature: (Scalar, RistrettoPoint)) -> bool {
        let verification_hash = Scalar::from_hash(
            Sha512::new()
                .chain(signature.1.compress().to_bytes())
                .chain(self.0.compress().to_bytes())
                .chain(message.compress().to_bytes()),
        );

        let check =
            &signature.0 * &RISTRETTO_BASEPOINT_TABLE == signature.1 + verification_hash * self.0;
        check
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Generate public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> PublicKey {
        PublicKey(CompressedRistretto::from_slice(bytes).decompress().unwrap())
    }

    /// Generates public key from RistrettoPoint
    pub fn from_point(point: RistrettoPoint) -> PublicKey {
        PublicKey(point)
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
    pub fn new<T: Rng + CryptoRng>(csprng: &mut T) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        SecretKey(clamp_scalar(bytes))
    }

    /// Decrypt ciphertexts
    pub fn decrypt(&self, ciphertext: Ciphertext) -> RistrettoPoint {
        let (point1, point2) = ciphertext.get_points();
        point2 - point1 * self.0
    }

    /// Partially decrypts a ciphertext
    pub fn partial_decrypt(self, ct: Ciphertext) -> Ciphertext {
        let (point1, point2) = ct.get_points();
        Ciphertext {
            pk: ct.pk,
            points: (point1, point2 - point1 * self.0),
        }
    }

    /// Sign a message using EdDSA algorithm.
    pub fn sign(&self, message: RistrettoPoint) -> (Scalar, RistrettoPoint) {
        let pk = PublicKey::from(self);
        let random_signature = Scalar::from_hash(
            Sha512::new()
                .chain(message.compress().to_bytes())
                .chain(self.0.to_bytes()),
        );
        let signature_point = &random_signature * &RISTRETTO_BASEPOINT_TABLE;

        let signature_scalar = random_signature
            + Scalar::from_hash(
                Sha512::new()
                    .chain(signature_point.compress().to_bytes())
                    .chain(pk.0.compress().to_bytes())
                    .chain(message.compress().to_bytes()),
            ) * self.0;

        (signature_scalar, signature_point)
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

impl<'a> From<&'a SecretKey> for PublicKey {
    /// Given a secret key, compute its corresponding Public key
    fn from(secret: &'a SecretKey) -> PublicKey {
        PublicKey(&RISTRETTO_BASEPOINT_TABLE * &secret.0)
    }
}

// "Decode" a scalar from a 32-byte array. Read more regarding this key clamping.
fn clamp_scalar(scalar: [u8; 32]) -> Scalar {
    let mut s: [u8; 32] = scalar.clone();
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    Scalar::from_bits(s)
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct Ciphertext {
    pub pk: PublicKey,
    pub points: (RistrettoPoint, RistrettoPoint),
}

impl Ciphertext {
    pub fn get_points(self) -> (RistrettoPoint, RistrettoPoint) {
        return (self.points.0, self.points.1);
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    fn test_encryption() {
        let mut csprng = OsRng::new().unwrap();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt = RistrettoPoint::random(&mut csprng);

        let ctxt = pk.encrypt(ptxt);
        assert_eq!(ptxt, sk.decrypt(ctxt));
    }

    #[test]
    fn test_encryption_dirty() {
        let mut csprng = OsRng::new().unwrap();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt = RistrettoPoint::random(&mut csprng);
        unsafe {
            let mut random_encryption = Scalar::random(&mut csprng);
            let ctxt = pk.encrypt_dirty(ptxt, random_encryption);
            random_encryption.clear();
            assert_eq!(ptxt, sk.decrypt(ctxt));
        }
    }

    #[test]
    fn test_byte_conversion() {
        let mut csprng = OsRng::new().unwrap();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let pk_byte = pk.to_bytes();
        let pk_from_bytes = PublicKey::from_bytes(&pk_byte);

        assert_eq!(pk, pk_from_bytes);
    }

    #[test]
    fn test_signature() {
        let mut csprng = OsRng::new().unwrap();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let msg = RistrettoPoint::random(&mut csprng);
        let signature = sk.sign(msg);
        assert!(pk.verify(&msg, signature));
    }

    #[test]
    fn test_signature_failure() {
        let mut csprng = OsRng::new().unwrap();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let msg = RistrettoPoint::random(&mut csprng);
        let msg_unsigned = RistrettoPoint::random(&mut csprng);
        let signature = sk.sign(msg);

        assert!(!pk.verify(&msg_unsigned, signature));
    }

    #[test]
    fn test_homomorphic_addition() {
        let mut csprng = OsRng::new().unwrap();
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
        let mut csprng = OsRng::new().unwrap();
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
        let mut csprng = OsRng::new().unwrap();
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
        let mut csprng = OsRng::new().unwrap();
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

        let mut csprng = OsRng::new().unwrap();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let encoded = bincode::serialize(&pk).unwrap();
        let decoded: PublicKey = bincode::deserialize(&encoded).unwrap();

        assert_eq!(pk, decoded);
    }

    #[test]
    fn test_serde_ciphertext() {
        use bincode;

        let mut csprng = OsRng::new().unwrap();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext: RistrettoPoint = RistrettoPoint::random(&mut csprng);
        let enc_plaintext = pk.encrypt(plaintext);

        let encoded = bincode::serialize(&enc_plaintext).unwrap();
        let decoded: Ciphertext = bincode::deserialize(&encoded).unwrap();

        assert_eq!(enc_plaintext.pk, decoded.pk);
        assert_eq!(enc_plaintext.points, decoded.points);
    }
}
