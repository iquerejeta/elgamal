use core::ops::{Add, Div, Mul, Sub};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::public::*;
use curve25519_dalek_ng::constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT};
use rand_core::OsRng;
use zkp::{CompactProof, Transcript};

define_proof! {dleq, "DLEQ Proof", (x), (A, B, H), (G) : A = (x * B), H = (x * G)}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct Ciphertext {
    pub pk: PublicKey,
    pub points: (RistrettoPoint, RistrettoPoint),
}

impl Ciphertext {
    pub fn get_points(self) -> (RistrettoPoint, RistrettoPoint) {
        (self.points.0, self.points.1)
    }

    pub fn randomise_ciphertext_and_prove(self) -> (Ciphertext, CompactProof) {
        let randomiser = Scalar::random(&mut OsRng);
        let randomised_ciphertext = Ciphertext {
            pk: self.pk,
            points: (
                self.points.0 + randomiser * RISTRETTO_BASEPOINT_POINT,
                self.points.1 + randomiser * self.pk.get_point(),
            ),
        };

        let mut transcript = Transcript::new(b"CorrectRandomisation");
        let (proof, _) = dleq::prove_compact(
            &mut transcript,
            dleq::ProveAssignments {
                x: &randomiser,
                A: &(randomised_ciphertext.points.0 - self.points.0),
                B: &RISTRETTO_BASEPOINT_POINT,
                H: &(randomised_ciphertext.points.1 - self.points.1),
                G: &self.pk.get_point(),
            },
        );

        (randomised_ciphertext, proof)
    }

    pub fn verify_randomisation(self, plain_ciphertext: &Ciphertext, proof: &CompactProof) -> bool {
        let mut transcript = Transcript::new(b"CorrectRandomisation");

        dleq::verify_compact(
            &proof,
            &mut transcript,
            dleq::VerifyAssignments {
                A: &(self.points.0 - plain_ciphertext.points.0).compress(),
                B: &RISTRETTO_BASEPOINT_COMPRESSED,
                H: &(self.points.1 - plain_ciphertext.points.1).compress(),
                G: &plain_ciphertext.pk.get_point().compress(),
            },
        )
        .is_ok()
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
                self.points.0 + other.points.0,
                self.points.1 + other.points.1,
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
                self.points.0 - other.points.0,
                self.points.1 - other.points.1,
            ),
        }
    }
}

define_sub_variants!(LHS = Ciphertext, RHS = Ciphertext, Output = Ciphertext);

impl<'a, 'b> Add<&'b Ciphertext> for &'a RistrettoPoint {
    type Output = Ciphertext;

    fn add(self, other: &'b Ciphertext) -> Ciphertext {
        Ciphertext {
            pk: other.pk,
            points: (other.points.0, self + other.points.1),
        }
    }
}

define_add_variants!(LHS = RistrettoPoint, RHS = Ciphertext, Output = Ciphertext);

impl<'a, 'b> Add<&'b RistrettoPoint> for &'a Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: &'b RistrettoPoint) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (self.points.0, self.points.1 + other),
        }
    }
}

define_add_variants!(LHS = Ciphertext, RHS = RistrettoPoint, Output = Ciphertext);

impl<'a, 'b> Sub<&'b Ciphertext> for &'a RistrettoPoint {
    type Output = Ciphertext;

    fn sub(self, other: &'b Ciphertext) -> Ciphertext {
        Ciphertext {
            pk: other.pk,
            points: (-other.points.0, self - other.points.1),
        }
    }
}

define_sub_variants!(LHS = RistrettoPoint, RHS = Ciphertext, Output = Ciphertext);

impl<'a, 'b> Sub<&'b RistrettoPoint> for &'a Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: &'b RistrettoPoint) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (self.points.0, self.points.1 - other),
        }
    }
}

define_sub_variants!(LHS = Ciphertext, RHS = RistrettoPoint, Output = Ciphertext);

impl<'a, 'b> Mul<&'b Scalar> for &'a Ciphertext {
    type Output = Ciphertext;

    fn mul(self, other: &'b Scalar) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (self.points.0 * other, self.points.1 * other),
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
                self.points.0 * other.invert(),
                self.points.1 * other.invert(),
            ),
        }
    }
}

define_div_variants!(LHS = Ciphertext, RHS = Scalar, Output = Ciphertext);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private::SecretKey;
    use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    fn test_randomisation_and_proof() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt = RistrettoPoint::random(&mut csprng);
        let ctxt = pk.encrypt(&ptxt);

        // Randomise and prove
        let (randomised_ctxt, proof) = ctxt.randomise_ciphertext_and_prove();

        assert_eq!(sk.decrypt(&randomised_ctxt), ptxt);
        assert!(randomised_ctxt.verify_randomisation(&ctxt, &proof));
    }

    #[test]
    fn test_failed_randomisation_and_proof() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt = RistrettoPoint::random(&mut csprng);
        let ctxt = pk.encrypt(&ptxt);
        let ctxt_rnd = pk.encrypt(&ptxt);

        // Randomise and prove
        let (randomised_ctxt, proof) = ctxt.randomise_ciphertext_and_prove();

        assert_eq!(sk.decrypt(&randomised_ctxt), ptxt);
        assert!(!ctxt_rnd.verify_randomisation(&ctxt, &proof));
    }

    #[test]
    fn test_homomorphic_addition() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt1 = RistrettoPoint::random(&mut csprng);
        let ptxt2 = RistrettoPoint::random(&mut csprng);

        let ctxt1 = pk.encrypt(&ptxt1);
        let ctxt2 = pk.encrypt(&ptxt2);

        let encrypted_addition = ctxt1 + ctxt2;
        let decrypted_addition = sk.decrypt(&encrypted_addition);

        assert_eq!(ptxt1 + ptxt2, decrypted_addition);
    }

    #[test]
    fn test_homomorphic_subtraction() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt1 = RistrettoPoint::random(&mut csprng);
        let ptxt2 = RistrettoPoint::random(&mut csprng);

        let ctxt1 = pk.encrypt(&ptxt1);
        let ctxt2 = pk.encrypt(&ptxt2);

        let encrypted_addition = ctxt1 - ctxt2;
        let decrypted_addition = sk.decrypt(&encrypted_addition);

        assert_eq!(ptxt1 - ptxt2, decrypted_addition);
    }

    #[test]
    fn test_add_of_ciphertext_and_plaintext() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);
        let plaintext2 = RistrettoPoint::random(&mut csprng);

        assert!(sk.decrypt(&(plaintext2 + ciphertext)) == plaintext + plaintext2);
        assert!(sk.decrypt(&(ciphertext + plaintext2)) == plaintext + plaintext2);
    }

    #[test]
    fn test_sub_of_ciphertext_and_plaintext() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);
        let plaintext2 = RistrettoPoint::random(&mut csprng);

        assert!(sk.decrypt(&(plaintext2 - ciphertext)) == plaintext2 - plaintext);
        assert!(sk.decrypt(&(ciphertext - plaintext2)) == plaintext - plaintext2);
    }

    #[test]
    fn test_multiplication_by_scalar() {
        // generates public private pair
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let pltxt: RistrettoPoint = RistrettoPoint::random(&mut csprng);
        let enc_pltxt = pk.encrypt(&pltxt);

        let mult_factor: Scalar = Scalar::random(&mut csprng);
        let mult_pltxt = pltxt * mult_factor;
        let mult_ctxt = enc_pltxt * mult_factor;
        let mult_dec_pltxt = sk.decrypt(&mult_ctxt);

        assert_eq!(mult_dec_pltxt, mult_pltxt);
    }

    #[test]
    fn test_division_by_scalar() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let div_factor: Scalar = Scalar::random(&mut csprng);
        let pltxt: RistrettoPoint = div_factor * RISTRETTO_BASEPOINT_POINT;
        let enc_pltxt = pk.encrypt(&pltxt);

        let div_ctxt = enc_pltxt / div_factor;
        let div_dec_pltxt = sk.decrypt(&div_ctxt);

        assert_eq!(div_dec_pltxt, RISTRETTO_BASEPOINT_POINT);
    }

    #[test]
    fn test_serde_ciphertext() {
        use bincode;

        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext: RistrettoPoint = RistrettoPoint::random(&mut csprng);
        let enc_plaintext = pk.encrypt(&plaintext);

        let encoded = bincode::serialize(&enc_plaintext).unwrap();
        let decoded: Ciphertext = bincode::deserialize(&encoded).unwrap();

        assert_eq!(enc_plaintext.pk, decoded.pk);
        assert_eq!(enc_plaintext.points, decoded.points);
    }
}
