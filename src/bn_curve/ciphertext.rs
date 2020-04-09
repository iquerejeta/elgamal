use core::ops::{Add, Div, Mul, Sub};
use bn::{Fr, G1, Group};
use serde::{Deserialize, Serialize};

use crate::bn_curve::public::*;
use rand_core::OsRng;
use rand::{thread_rng};

#[derive(Copy, Clone)]
pub struct Ciphertext {
    pub pk: PublicKey,
    pub points: (G1, G1),
}

impl Ciphertext {
    pub fn get_points(self) -> (G1, G1) {
        return (self.points.0, self.points.1);
    }
}

impl Add<Ciphertext> for Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: Ciphertext) -> Ciphertext {
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

impl Sub<Ciphertext> for Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: Ciphertext) -> Ciphertext {
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

impl Add<Ciphertext> for G1 {
    type Output = Ciphertext;

    fn add(self, other: Ciphertext) -> Ciphertext {
        Ciphertext {
            pk: other.pk,
            points: (other.points.0, self + other.points.1),
        }
    }
}

impl Add<G1> for Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: G1) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (self.points.0, self.points.1 + other),
        }
    }
}

impl Sub<Ciphertext> for G1 {
    type Output = Ciphertext;

    fn sub(self, other: Ciphertext) -> Ciphertext {
        Ciphertext {
            pk: other.pk,
            points: (-other.points.0, self - other.points.1),
        }
    }
}

impl Sub<G1> for Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: G1) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (self.points.0, self.points.1 - other),
        }
    }
}

impl Mul<Fr> for Ciphertext {
    type Output = Ciphertext;

    fn mul(self, other: Fr) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (self.points.0 * other, self.points.1 * other),
        }
    }
}

impl Div<Fr> for Ciphertext {
    type Output = Ciphertext;

    fn div(self, other: Fr) -> Ciphertext {
        Ciphertext {
            pk: self.pk,
            points: (
                self.points.0 * other.inverse().unwrap(),
                self.points.1 * other.inverse().unwrap(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn_curve::private::SecretKey;

    #[test]
    fn test_homomorphic_addition() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt1 = G1::random(&mut csprng);
        let ptxt2 = G1::random(&mut csprng);

        let ctxt1 = pk.encrypt(&ptxt1);
        let ctxt2 = pk.encrypt(&ptxt2);

        let encrypted_addition = ctxt1 + ctxt2;
        let decrypted_addition = sk.decrypt(&encrypted_addition);

        let check = ptxt1 + ptxt2 == decrypted_addition;
        assert!(check);
    }

    #[test]
    fn test_homomorphic_subtraction() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ptxt1 = G1::random(&mut csprng);
        let ptxt2 = G1::random(&mut csprng);

        let ctxt1 = pk.encrypt(&ptxt1);
        let ctxt2 = pk.encrypt(&ptxt2);

        let encrypted_addition = ctxt1 - ctxt2;
        let decrypted_addition = sk.decrypt(&encrypted_addition);

        let check = ptxt1 - ptxt2 == decrypted_addition;
        assert!(check);
    }

    #[test]
    fn test_add_of_ciphertext_and_plaintext() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = G1::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);
        let plaintext2 = G1::random(&mut csprng);

        assert!(sk.decrypt(&(plaintext2 + ciphertext)) == plaintext + plaintext2);
        assert!(sk.decrypt(&(ciphertext + plaintext2)) == plaintext + plaintext2);
    }

    #[test]
    fn test_sub_of_ciphertext_and_plaintext() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = G1::random(&mut csprng);
        let ciphertext = pk.encrypt(&plaintext);
        let plaintext2 = G1::random(&mut csprng);

        assert!(sk.decrypt(&(plaintext2 - ciphertext)) == plaintext2 - plaintext);
        assert!(sk.decrypt(&(ciphertext - plaintext2)) == plaintext - plaintext2);
    }

    #[test]
    fn test_multiplication_by_scalar() {
        // generates public private pair
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let pltxt: G1 = G1::random(&mut csprng);
        let enc_pltxt = pk.encrypt(&pltxt);

        let mult_factor: Fr = Fr::random(&mut csprng);
        let mult_pltxt = pltxt * mult_factor;
        let mult_ctxt = enc_pltxt * mult_factor;
        let mult_dec_pltxt = sk.decrypt(&mult_ctxt);

        let check = mult_dec_pltxt == mult_pltxt;
        assert!(check);
    }

    #[test]
    fn test_division_by_scalar() {
        let mut csprng = thread_rng();
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let div_factor: Fr = Fr::random(&mut csprng);
        let pltxt: G1 = G1::one() * div_factor;
        let enc_pltxt = pk.encrypt(&pltxt);

        let div_ctxt = enc_pltxt / div_factor;
        let div_dec_pltxt = sk.decrypt(&div_ctxt);

        let check = div_dec_pltxt == G1::one();
        assert!(check);
    }

    // #[test]
    // fn test_serde_ciphertext() {
    //     use bincode;
    //
    //     let mut csprng = OsRng;
    //     let sk = SecretKey::new(&mut csprng);
    //     let pk = PublicKey::from(&sk);
    //
    //     let plaintext: RistrettoPoint = RistrettoPoint::random(&mut csprng);
    //     let enc_plaintext = pk.encrypt(&plaintext);
    //
    //     let encoded = bincode::serialize(&enc_plaintext).unwrap();
    //     let decoded: Ciphertext = bincode::deserialize(&encoded).unwrap();
    //
    //     assert_eq!(enc_plaintext.pk, decoded.pk);
    //     assert_eq!(enc_plaintext.points, decoded.points);
    // }
}
