#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
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

extern crate alloc;

use alloc::string::String;

/// JSON Web Encryption: a data structure representing an encrypted and
/// integrity-protected message.
pub struct Jwe {
    /// One of the JOSE JWE header types; see [`Header`]
    pub header: Header,

    /// Encrypted Content Encryption Key value.  Note that for some algorithms,
    /// the JWE Encrypted Key value is specified as being the empty octet
    /// sequence.
    pub encrypted_key: String,

    /// Initialization Vector value used when encrypting the plaintext. Note
    /// that some algorithms may not use an Initialization Vector, in which case
    /// this value is the empty octet sequence.
    pub init_vector: String,

    /// Additional value to be integrity protected by the authenticated
    /// encryption operation.  This can only be present when using the JWE JSON
    /// Serialization.  (Note that this can also be achieved when using either
    /// the JWE Compact Serialization or the JWE JSON Serialization by including
    /// the AAD value as an integrity-protected Header Parameter value, but at
    /// the cost of the value being double base64url encoded.)
    pub aad: Option<String>,
    
    /// Ciphertext value resulting from authenticated encryption of the
    /// plaintext with Additional Authenticated Data.
    pub cyphertext: String,

    /// Authentication Tag value resulting from authenticated encryption of the
    /// plaintext with Additional Authenticated Data.
    pub auth_tag: String,
}


/// One of the JWE header types
#[non_exhaustive]
pub enum Header {
    /// JWE Protected Header
    /// 
    /// JSON object that contains the Header Parameters that are integrity
    /// protected by the authenticated encryption operation.  These parameters
    /// apply to all recipients of the JWE.  For the JWE Compact Serialization,
    /// this comprises the entire JOSE Header.  For the JWE JSON Serialization,
    /// this is one component of the JOSE Header.
    Protected(String),

    /// JWE Shared Unprotected Header
    /// 
    /// JSON object that contains the Header Parameters that apply to all
    /// recipients of the JWE that are not integrity protected.  This can only
    /// be present when using the JWE JSON Serialization.
    Unprotected(String),

    /// JWE Per-Recipient Unprotected Header
    /// 
    /// JSON object that contains Header Parameters that apply to a single
    /// recipient of the JWE.  These Header Parameter values are not integrity
    /// protected.  This can only be present when using the JWE JSON
    /// Serialization.
    PerRecipientUnprotected(String),
}
