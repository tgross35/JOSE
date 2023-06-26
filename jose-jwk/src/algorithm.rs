//! Algorithms for JWKs
//!
//! Technically these are defined in the JWA RFC, but it makes more sense to
//! keep them here

use core::fmt;

use serde::{Deserialize, Serialize};

/// Possible key algorithms as defineed in the JWA [RFC7518]
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Algorithm {
    /// Algorithms for digital signatures and MACs
    Signing(SigningAlg),
    /// Algorithms for key managdment
    KeyManagement(KeyMgmtAlg),
    /// Algorithms for encryption
    Encryption(EncryptionAlg),
}

/// Algorithms used for digital signatures and MACs, as defined in [RFC7518]
/// section 3.1. Used for JWS `alg` parameter.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SigningAlg {
    /// EdDSA signature algorithms (Optional)
    #[serde(rename = "EdDSA")]
    EdDsa,

    /// ECDSA using P-256 and SHA-256 (Recommended+)
    Es256,

    /// ECDSA using secp256k1 curve and SHA-256 (Optional)
    Es256K,

    /// ECDSA using P-384 and SHA-384 (Optional)
    Es384,

    /// ECDSA using P-521 and SHA-512 (Optional)
    Es512,

    /// HMAC using SHA-256 (Required)
    Hs256,

    /// HMAC using SHA-384 (Optional)
    Hs384,

    /// HMAC using SHA-512 (Optional)
    Hs512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (Optional)
    Ps256,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (Optional)
    Ps384,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (Optional)
    Ps512,

    /// RSASSA-PKCS1-v1_5 using SHA-256 (Recommended)
    Rs256,

    /// RSASSA-PKCS1-v1_5 using SHA-384 (Optional)
    Rs384,

    /// RSASSA-PKCS1-v1_5 using SHA-512 (Optional)
    Rs512,

    /// No digital signature or MAC performed (Optional)
    #[serde(rename = "none")]
    None,
}

impl fmt::Display for SigningAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}

/// Algorithms used for key managment, as defined in [RFC7518] section 4.1. Used
/// for JWE `alg` parameter.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeyMgmtAlg {
    /// RSAES-PKCS1-v1_5 (Recommended-)
    #[serde(rename = "RSA1_5")]
    Rsa1to5,

    /// RSAES OAEP using default parameters (Recommended+)
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,

    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256 (Optional)
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,

    /// AES Key Wrap with default initial value using 128-bit key (Recommended)
    #[serde(rename = "A128KW")]
    Aes128Kw,

    /// AES Key Wrap with default initial value using 192-bit key (Optional)
    #[serde(rename = "A192KW")]
    Aes192Kw,

    /// AES Key Wrap with default initial value using 256-bit key (Recommended)
    #[serde(rename = "A256KW")]
    Aes256Kw,

    /// Direct use of a shared symmetric key as the CEK (Recommended)
    #[serde(rename = "dir")]
    Dir,

    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using
    /// Concat KDF (Recommended+)
    #[serde(rename = "ECDH-ES")]
    EcdhEs,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW" (Recommended)
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128Kw,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW" (Optional)
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsA192Kw,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW" (Recommended)
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,

    /// Key wrapping with AES GCM using 128-bit key (Optional)
    #[serde(rename = "A128GCMKW")]
    Aes128GcmKw,

    /// Key wrapping with AES GCM using 192-bit key (Optional)
    #[serde(rename = "A192GCMKW")]
    Aes192GcmKw,

    /// Key wrapping with AES GCM using 256-bit key (Optional)
    #[serde(rename = "A256GCMKW")]
    Aes256GcmKw,

    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping (Optional)
    #[serde(rename = "PBES2-HS256+A128KW")]
    Pbes2Hs256A128Kw,

    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping (Optional)
    #[serde(rename = "PBES2-HS384+A192KW")]
    Pbes2Hs384A192Kw,

    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping (Optional)
    #[serde(rename = "PBES2-HS512+A256KW")]
    Pbes2Hs512A256Kw,
}

impl fmt::Display for KeyMgmtAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}

/// Algorithms used for encryption, as defined in [RFC7518] section 5.1. Used
/// for JWE `enc` parameter.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EncryptionAlg {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined
    /// in RFC7518 Section 5.2.3 (Required)
    #[serde(rename = "A128CBC-HS256")]
    Aes128CbcHs256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined
    /// in RFC7518 Section 5.2.4 (Optional)
    #[serde(rename = "A192CBC-HS384")]
    Aes192CbcHs384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined
    /// in RFC7518 Section 5.2.5 (Required)
    #[serde(rename = "A256CBC-HS512")]
    Aes256CbcHs512,
    /// AES GCM using 128-bit key (Recommended)
    #[serde(rename = "A128GCM")]
    Aes128Gcm,
    /// AES GCM using 192-bit key (Optional)
    #[serde(rename = "A192GCM")]
    Aes192Gcm,
    /// AES GCM using 256-bit key (Recommended)
    #[serde(rename = "A256GCM")]
    Aes256Gcm,
}

impl fmt::Display for EncryptionAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}
