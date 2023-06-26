#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

mod algorithm;
mod key;

use alloc::{boxed::Box, collections::BTreeSet, string::String, vec::Vec};
use jose_b64::{base64ct::Base64, B64Bytes};
use serde::{Deserialize, Serialize};

pub use algorithm::{Algorithm, EncryptionAlg, KeyMgmtAlg, SigningAlg};
pub use key::{Ec, EcCurve, Key, Oct, Okp, OkpCurve, OkpPrivate, Rsa, RsaOtherPrimes, RsaPrivate};

extern crate alloc;

/// Strongly typed JWK
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    /// The key itself. This field contains the important information, all other
    /// top-level fields are
    #[serde(flatten)]
    pub key: Key,

    #[serde(flatten)]
    pub params: Parameters,
}

impl Jwk {
    /// Create a new JWK from a key, using default parameters
    pub fn new(key: Key) -> Self {
        Self {
            key,
            params: Default::default(),
        }
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Parameters {
    /// The algorithm used with this key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<Algorithm>,

    /// Identifier of this key
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,

    /// Intended use of this public key (named `use` in the rfc)
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub use_for: Option<UseFor>,

    /// Intended operations for this key; optional
    #[serde(skip_serializing_if = "BTreeSet::is_empty", default)]
    pub key_ops: BTreeSet<Operations>,

    /// X.509 options
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub x509: Option<Box<X509>>,
}

/// Additional X.509 options for a JWK
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct X509 {
    /// The URL of the X.509 certificate associated with this key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[cfg(feature = "url")]
    pub x5u: Option<url::Url>,

    /// The X.509 certificate associated with this key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub x5c: Option<Vec<B64Bytes<Box<[u8]>, Base64>>>, // base64, not base64url

    /// An X.509 thumbprint (SHA-1).
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5t", default)]
    pub x5t: Option<B64Bytes<[u8; 20]>>,

    /// An X.509 thumbprint (SHA-2 256).
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5t#S256", default)]
    pub x5t_s256: Option<B64Bytes<[u8; 32]>>,
}

/// A set of JSON Web Keys.
///
/// This type is defined in [RFC7517 Section 5].
///
/// [RFC7517 Section 5]: https://datatracker.ietf.org/doc/html/rfc7517#section-5
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct JwkSet {
    /// The keys in the set.
    pub keys: Vec<Jwk>,
}

/// Intended use of this key
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum UseFor {
    /// The key should be used for encryption
    #[serde(rename = "enc")]
    Encryption,
    /// The key should be used for signing
    #[serde(rename = "sig")]
    Signing,
}

/// Possible values for `key_ops`, specified in RFC7517 section 4.3.
// NOTE: Keep in lexicographical order for BTreeSet
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Operations {
    /// Decrypt content and validate decryption, if applicable
    Decrypt,
    /// Derive bits not to be used as a key
    DeriveBits,
    /// Derive key
    DeriveKey,
    /// Encrypt key
    Encrypt,
    /// Compute digital signature or MAC
    Sign,
    /// Decrypt key and validate decryption, if applicable
    UnwrapKey,
    /// Verify digital signature or MAC
    Verify,
    /// Encrypt content
    WrapKey,
}
