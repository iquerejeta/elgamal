extern crate elgamal_ristretto;

use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{OsRng, };

use elgamal_ristretto::public::PublicKey;
use elgamal_ristretto::private::SecretKey;
use elgamal_ristretto::ciphertext::Ciphertext;

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
    fn prove_and_verify_correct_randomization() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let ciphertext = pk.encrypt(plaintext);
        let (randomized_ciphertext, proof) = ciphertext.randomize_plaintext_and_prove();

        assert!(randomized_ciphertext.verify_correct_randomization(ciphertext, proof));
    }

    #[test]
    fn prove_and_verify_incorrect_randomization() {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let plaintext = RistrettoPoint::random(&mut csprng);
        let ciphertext = pk.encrypt(plaintext);
        let (_, proof) = ciphertext.randomize_plaintext_and_prove();
        let fake_randomized = ciphertext * Scalar::from(12u16);

        assert!(!fake_randomized.verify_correct_randomization(ciphertext, proof));
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
}