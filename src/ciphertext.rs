use core::ops::{Add, Div, Mul, Sub};
use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use rand_core::{OsRng, };

use zkp::{Transcript, CompactProof, };

use crate::public::*;

define_proof! {dleq, "DLEQ Proof", (x), (A, B, H), (G) : A = (x * B), H = (x * G)}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct Ciphertext {
    pub pk: PublicKey,
    pub points: (RistrettoPoint, RistrettoPoint),
}

impl Ciphertext {
    pub fn get_points(self) -> (RistrettoPoint, RistrettoPoint) {
        return (self.points.0, self.points.1);
    }

    /// Randomize a ciphertext's plaintext and prove correctness.
    pub fn randomize_plaintext_and_prove(self) -> (Ciphertext, CompactProof) {
        let randomizer = Scalar::random(&mut OsRng);

        let randomized_ciphertext = Ciphertext{
            pk: self.pk,
            points: (self.points.0 * randomizer, self.points.1 * randomizer)
        };

        let mut transcript = Transcript::new(b"CorrectRandomization");
        let (proof, _) = dleq::prove_compact(
            &mut transcript,
            dleq::ProveAssignments {
                x: &randomizer,
                A: &randomized_ciphertext.points.0,
                B: &self.points.0,
                H: &randomized_ciphertext.points.1,
                G: &self.points.1,
            },
        );

        (randomized_ciphertext, proof)
    }

    /// Verify proof of correct randomization
    pub fn verify_correct_randomization(
        self,
        initial_ciphertext: Ciphertext,
        proof: CompactProof
    ) -> bool {
        let mut transcript = Transcript::new(b"CorrectRandomization");
        dleq::verify_compact(
            &proof,
            &mut transcript,
            dleq::VerifyAssignments {
                A: &self.points.0.compress(),
                B: &initial_ciphertext.points.0.compress(),
                H: &self.points.1.compress(),
                G: &initial_ciphertext.points.1.compress(),
            },
        ).is_ok()
        // verify_dlog_knowledge_proof(self.pk.get_point().compress(), value.compress(), proof)
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