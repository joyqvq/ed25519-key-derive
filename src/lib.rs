// A clone of ed25519-dalek-bip32 without fail on the index is normal #L95-L97. 

//! A simple BIP32 implementation for ed25519 public keys. Although there exists [another very good
//! library that does this](https://docs.rs/ed25519-bip32), this library preserves 32 byte secret
//! keys and doesn't allow for extended public keys or "normal" child indexes, so that it can be as
//! close to the BIP32 specifications as possible, allowing for compatibility with libraries like
//! `trezor-crypto`

#![cfg_attr(not(feature = "std"), no_std)]

pub extern crate derivation_path;
pub extern crate ed25519_dalek;

pub use derivation_path::{ChildIndex, DerivationPath};
pub use ed25519_dalek::{PublicKey, SecretKey};

use core::fmt;
use hmac::{Hmac, Mac};
use sha2::Sha512;

const ED25519_BIP32_NAME: &str = "ed25519 seed";

/// Errors thrown while deriving secret keys
#[derive(Debug)]
pub enum Error {
    Ed25519,
    ExpectedHardenedIndex(ChildIndex),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 => f.write_str("ed25519 error"),
            Self::ExpectedHardenedIndex(index) => {
                f.write_fmt(format_args!("expected hardened child index: {}", index))
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// An expanded secret key with chain code and meta data
#[derive(Debug)]
pub struct ExtendedSecretKey {
    /// How many derivations this key is from the root (0 for root)
    pub depth: u8,
    /// Child index of the key used to derive from parent (`Normal(0)` for root)
    pub child_index: ChildIndex,
    /// Secret Key
    pub secret_key: SecretKey,
    /// Chain code
    pub chain_code: [u8; 32],
}

type HmacSha512 = Hmac<Sha512>;

/// A convenience wrapper for a [`core::result::Result`] with an [`Error`]
pub type Result<T, E = Error> = core::result::Result<T, E>;

impl ExtendedSecretKey {
    /// Create a new extended secret key from a seed
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let mut mac = HmacSha512::new_from_slice(ED25519_BIP32_NAME.as_ref()).unwrap();
        mac.update(seed);
        let bytes = mac.finalize().into_bytes();

        let secret_key = SecretKey::from_bytes(&bytes[..32])?;
        let mut chain_code = [0; 32];
        chain_code.copy_from_slice(&bytes[32..]);

        Ok(Self {
            depth: 0,
            child_index: ChildIndex::Normal(0),
            secret_key,
            chain_code,
        })
    }

    /// Derive an extended secret key fom the current using a derivation path
    pub fn derive<P: AsRef<[ChildIndex]>>(&self, path: &P) -> Result<Self> {
        let mut path = path.as_ref().iter();
        let mut next = match path.next() {
            Some(index) => self.derive_child(*index)?,
            None => self.clone(),
        };
        for index in path {
            next = next.derive_child(*index)?;
        }
        Ok(next)
    }

    /// Derive a child extended secret key with an index
    pub fn derive_child(&self, index: ChildIndex) -> Result<Self> {
        // if index.is_normal() {
        //     return Err(Error::ExpectedHardenedIndex(index));
        // }

        let mut mac = HmacSha512::new_from_slice(&self.chain_code).unwrap();
        mac.update(&[0u8]);
        mac.update(self.secret_key.to_bytes().as_ref());
        mac.update(index.to_bits().to_be_bytes().as_ref());
        let bytes = mac.finalize().into_bytes();

        let secret_key = SecretKey::from_bytes(&bytes[..32])?;
        let mut chain_code = [0; 32];
        chain_code.copy_from_slice(&bytes[32..]);

        Ok(Self {
            depth: self.depth + 1,
            child_index: index,
            secret_key,
            chain_code,
        })
    }

    /// Get the associated public key
    #[inline]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret_key)
    }

    #[inline]
    fn clone(&self) -> Self {
        Self {
            depth: self.depth,
            child_index: self.child_index,
            secret_key: SecretKey::from_bytes(&self.secret_key.to_bytes()).unwrap(),
            chain_code: self.chain_code,
        }
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        Self::Ed25519
    }
}