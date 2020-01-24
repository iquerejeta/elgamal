#![feature(external_doc)]

#[macro_use]
extern crate zkp;
#[macro_use]
pub mod macros;

#[doc(include = "../docs/intro.md")]
mod notes {
    #[doc(include = "../docs/notes-elgamal.md")]
    mod elgamal_cryptosystem {}
    #[doc(include = "../docs/notes-zkps.md")]
    mod zkps {}
}

pub mod ciphertext;
pub mod private;
pub mod public;
