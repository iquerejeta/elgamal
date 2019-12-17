#[macro_use]
extern crate criterion;
use criterion::Criterion;

extern crate elgamal_ristretto;
extern crate rand;
extern crate curve25519_dalek;

use elgamal_ristretto::public::{PublicKey, };
use elgamal_ristretto::private::{SecretKey, };
use rand_core::OsRng;
use curve25519_dalek::ristretto::RistrettoPoint;

fn encrypt_ciphertext(c: &mut Criterion) {
    let label = format!("Encryption");
    c.bench_function(
        &label,
        move |b| {
            let mut csprng = OsRng;
            let sk = SecretKey::new(&mut csprng);
            let pk = PublicKey::from(&sk);

            let ptxt = RistrettoPoint::random(&mut csprng);

            b.iter(|| {
                pk.encrypt(ptxt);
            })
        }
    );
}

fn decrypt_ciphertext(c: &mut Criterion) {
    let label = format!("Decryption");
    c.bench_function(
        &label,
        move |b| {
            let mut csprng = OsRng;
            let sk = SecretKey::new(&mut csprng);
            let pk = PublicKey::from(&sk);

            let ptxt = RistrettoPoint::random(&mut csprng);
            let ctxt = pk.encrypt(ptxt);

            b.iter(|| {
                sk.decrypt(ctxt);
            })
        }
    );
}

fn signature(c: &mut Criterion) {
    let label = format!("Signature");
    c.bench_function(
        &label,
        move |b| {
            let mut csprng = OsRng;
            let sk = SecretKey::new(&mut csprng);

            let msg = RistrettoPoint::random(&mut csprng);

            b.iter(|| {
                sk.sign(msg);
            })
        }
    );
}

fn verify_signature(c: &mut Criterion) {
    let label = format!("Verify Signature");
    c.bench_function(
        &label,
        move |b| {
            let mut csprng = OsRng;
            let sk = SecretKey::new(&mut csprng);
            let pk = PublicKey::from(&sk);

            let msg = RistrettoPoint::random(&mut csprng);
            let signature = sk.sign(msg);

            b.iter(|| {
                pk.verify_signature(&msg, signature)
            })
        }
    );
}

fn ciphertext_addition(c: &mut Criterion) {
    let label = format!("Ciphertext homomorphic addition");
    c.bench_function(
        &label,
        move |b| {
            let mut csprng = OsRng;
            let sk = SecretKey::new(&mut csprng);
            let pk = PublicKey::from(&sk);

            let ptxt1 = RistrettoPoint::random(&mut csprng);
            let ptxt2 = RistrettoPoint::random(&mut csprng);

            let ctxt1 = pk.encrypt(ptxt1);
            let ctxt2 = pk.encrypt(ptxt2);

            b.iter(|| {
                let _ = ctxt1 + ctxt2;
            })
        }
    );
}

criterion_group!(benches, encrypt_ciphertext, decrypt_ciphertext, signature, verify_signature, ciphertext_addition);
criterion_main!(benches);