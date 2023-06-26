use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use jose_b64::{B64Bytes, B64Secret};

/// A key type suitable for a JEK
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE", tag = "kty")]
pub enum Key {
    /// An elliptic curve key
    Ec(EcPublic),
    /// An RSA key
    Rsa(RsaPublic),
    /// A symmetric key
    #[serde(rename = "oct")]
    Oct(Oct),
}

impl Default for Key {
    fn default() -> Self {
        unimplemented!("There is no default for `Key`; it must always be set")
    }
}

/// An elliptic curve public key
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcPublic {
    /// DSS curve identifier
    pub crv: EcCurve,

    /// X coordinate for the elliptic curve point
    pub x: B64Bytes,

    /// y coordinate for the elliptic curve point
    pub y: B64Bytes,
}

/// An elliptic curve private key
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcPrivate {
    #[serde(flatten)]
    pub public: EcPublic,
    /// Private key value
    pub d: B64Secret,
}

/// An elliptic curve DSS identifier
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EcCurve {
    /// P-256
    #[serde(rename = "P-256")]
    P256,

    /// P-384
    #[serde(rename = "P-384")]
    P384,

    /// P-521
    #[serde(rename = "P-521")]
    P521,

    /// P-256K
    #[serde(rename = "secp256k1")]
    P256K,
}

/// An RSA key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPublic {
    /// RSA modulus parameter
    pub n: B64Bytes,

    /// RSA exponent parameter
    pub e: B64Bytes,
}

/// RSA key private material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPrivate {
    /// The public key associated with this private key
    #[serde(flatten)]
    pub public: RsaPublic,
    
    /// Private key exponent.
    pub d: B64Secret,

    /// Private first prime factor.
    pub p: Option<B64Secret>,

    /// Private second prime factor.
    pub q: Option<B64Secret>,

    /// Private first factor CRT exponent.
    pub dp: Option<B64Secret>,

    /// Private second factor CRT exponent.
    pub dq: Option<B64Secret>,

    /// Private first CRT coefficient.
    pub qi: Option<B64Secret>,

    /// Additional RSA private primes.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub oth: Vec<RsaOtherPrimes>,
}

/// Additional RSA private primes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaOtherPrimes {
    /// A private prime factor
    pub r: B64Secret,

    /// A private factor CRT exponent
    pub d: B64Secret,

    /// A private factor CRT coefficient
    pub t: B64Secret,
}

/// A symmetric octet key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Oct {
    /// The symmetric key.
    pub k: B64Secret,
}

impl From<EcPublic> for Key {
    fn from(key: EcPublic) -> Self {
        Self::Ec(key)
    }
}

impl From<RsaPublic> for Key {
    fn from(key: RsaPublic) -> Self {
        Self::Rsa(key)
    }
}

impl From<Oct> for Key {
    fn from(key: Oct) -> Self {
        Self::Oct(key)
    }
}
