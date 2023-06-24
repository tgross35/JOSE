use core::{convert::Infallible, fmt::Debug};

use alloc::{vec::Vec, boxed::Box};
use serde::{Serialize,Deserialize};
use jose_jwa::Algorithm;
use hmac::{Hmac, Mac, digest::InvalidLength};
use sha2::Sha256;

/// A single signature contains protected data, unprotected data, and then the
/// signature itself. The signature is the MAC of the payload plus the protected
/// header data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature<Phd, Uhd, Alg: MaybeSigned> {
    protected: Protected<Phd>,
    header: Uhd,
    /// "signature" value
    signature: Alg::SigData,
}

/// Protected header data
#[derive(Clone, Debug, Serialize,Deserialize)]
pub struct Protected<Phd> {
    /// When we sign, we always set the algorithm
    alg: Algorithm,
    /// Data that 
    #[serde(flatten)]
    extra: Phd,
}


/// Trait for both signed and unsigned data
pub trait MaybeSigned {
    /// Data representing signature type
    type SigData: Serialize;
}

/// Trait for all serializable algorithms
pub trait SigningAlg: MaybeSigned + Sized {
    const ALGORITHM: Algorithm;
    type Error: Debug;

    fn mac_new_from_slice(key: &[u8]) -> Result<Self, Self::Error>;
    fn mac_update(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn mac_finalize(self) -> Result<Self::SigData, Self::Error>;
}


/// Not yet signed. Note: does not implement serialized
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Unsigned {}

/// Signing algorithm is unknown for e.g., incoming JWEs where type may not be
/// known in advance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnySigning {}

impl MaybeSigned for Unsigned {
    type SigData = ();
}

type HmacSha256 = Hmac<Sha256>;

impl MaybeSigned for HmacSha256 {
    type SigData =  Box<[u8]>;
}

impl SigningAlg for HmacSha256 {
    const ALGORITHM: Algorithm = Algorithm::Hs256;

    type Error = Infallible;

    fn mac_new_from_slice(key: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::new_from_slice(key).unwrap())
    }
    
    fn mac_update(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.update(data);
        Ok(())
    }

    fn mac_finalize(self) -> Result<Self::SigData, Self::Error> {
        Ok(self.finalize().into_bytes().as_slice().into())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use crate::Empty;

    use super::*;
    use pretty_assertions::assert_eq;

    /// Dummy extra field for testing
    #[derive(Serialize)]
    struct Extra {
        a: &'static str,
        b: u64
    }

    #[test]
    fn test_protected() {
        // Test serializing extra data as flat
        let foo: Protected<Extra> = Protected { alg:Algorithm::None, extra: Extra {a: "foo", b: 100} };
        let expected = r#"{"alg":"none","a":"foo","b":100}"#;
        assert_eq!(serde_json::to_string(&foo).unwrap(), expected);

        // Test no extra data
        let foo: Protected<Empty> = Protected { alg:Algorithm::Es256, extra: () };
        let expected = r#"{"alg":"ES256"}"#;
        assert_eq!(serde_json::to_string(&foo).unwrap(), expected);
    }

    #[test]
    fn test_signature() {

    }
}
