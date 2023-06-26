use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use jose_b64::{B64Bytes, B64Secret};

/// A key type suitable for a JEK
// Note: keys must be sorted from most to least fields
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Key {
    /// Elliptic curve private key
    #[serde(rename = "EC")]
    EcPrivate(EcPrivate),
    /// An elliptic curve key
    #[serde(rename = "EC")]
    Ec(Ec),
    /// RSA private key
    #[serde(rename = "RSA")]
    RsaPrivate(RsaPrivate),
    /// An RSA key
    #[serde(rename = "RSA")]
    Rsa(Rsa),
    /// A symmetric key
    #[serde(rename = "oct")]
    Oct(Oct),
    /// OKP private key
    #[serde(rename = "OKP")]
    OkpPrivate(OkpPrivate),
    /// RFC8037 OKP key
    #[serde(rename = "OKP")]
    Okp(Okp),
}

/// An elliptic curve public key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ec {
    /// DSS curve identifier
    pub crv: EcCurve,

    /// X coordinate for the elliptic curve point
    pub x: B64Bytes,

    /// y coordinate for the elliptic curve point
    pub y: B64Bytes,
}

/// An elliptic curve private key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcPrivate {
    #[serde(flatten)]
    pub public: Ec,
    /// Private key value
    pub d: B64Secret,
}

/// An elliptic curve DSS identifier
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct Rsa {
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
    pub public: Rsa,

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

/// An octet key pair (OKP) key as defined in [RFC8037]
///
/// ```
/// use jose_jwk::{Jwk, Key, Okp, OkpPrivate, OkpCurve};
/// use hex_literal::hex;
///
/// let txt = r#"{
///     "kty":"OKP",
///     "crv":"Ed25519",
///     "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
///     "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
/// }"#;
///
/// let expected = Jwk::new(
///     OkpPrivate {
///         public: Okp {
///             crv: OkpCurve::Ed25519,
///             x: hex!("
///                 d7 5a 98 01 82 b1 0a b7 d5 4b fe d3 c9 64 07 3a
///                 0e e1 72 f3 da a6 23 25 af 02 1a 68 f7 07 51 1a
///             ").as_slice().into()
///         },
///         d: hex!(
///             "9d 61 b1 9d ef fd 5a 60 ba 84 4a f4 92 ec 2c c4
///             44 49 c5 69 7b 32 69 19 70 3b ac 03 1c ae 7f 60"
///        ).as_slice().into()
///     }.into()
/// );
/// dbg!(serde_json::to_string(&expected));
/// assert_eq!(expected, serde_json::from_str(txt).unwrap());
/// ```
///
/// [RFC8037]: https://www.rfc-editor.org/rfc/rfc8037
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Okp {
    /// The subtype of key pair
    pub crv: OkpCurve,

    /// The public key
    pub x: B64Bytes,
}

/// Private OKP key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkpPrivate {
    #[serde(flatten)]
    /// The subtype of key pair
    pub public: Okp,

    /// The private key
    pub d: B64Secret,
}

/// The CFRG Curve.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OkpCurve {
    /// Ed25519 signature algorithm key pairs
    Ed25519,

    /// Ed448 signature algorithm key pairs
    Ed448,

    /// X25519 function key pairs
    X25519,

    /// X448 function key pairs
    X448,
}

impl From<Ec> for Key {
    fn from(key: Ec) -> Self {
        Self::Ec(key)
    }
}

impl From<Rsa> for Key {
    fn from(key: Rsa) -> Self {
        Self::Rsa(key)
    }
}

impl From<Oct> for Key {
    fn from(key: Oct) -> Self {
        Self::Oct(key)
    }
}

impl From<Okp> for Key {
    fn from(key: Okp) -> Self {
        Self::Okp(key)
    }
}

impl From<OkpPrivate> for Key {
    fn from(key: OkpPrivate) -> Self {
        Self::OkpPrivate(key)
    }
}
