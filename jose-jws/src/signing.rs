use core::{convert::Infallible, fmt::Debug};

use alloc::{boxed::Box, vec::Vec};
use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{
    digest::{CtOutput, InvalidLength, KeyInit},
    Hmac, Mac,
};
use jose_b64::Json;
use jose_jwa::Algorithm;
use serde::{ser::SerializeMap, Deserialize, Serialize};

use crate::Empty;

pub type HmacSha256 = Hmac<sha2::Sha256>;
pub type HmacSha384 = Hmac<sha2::Sha384>;
pub type HmacSha512 = Hmac<sha2::Sha512>;

/// A single signature contains protected data, unprotected data, and then the
/// signature itself. The signature is the MAC of the payload plus the protected
/// header data.
#[derive(Clone, Debug)]
pub struct Signature<Phd, Uhd, Alg: MaybeSigned> {
    /// Protected header, base64 serialized
    pub(crate) protected: Json<Protected<Phd>>,
    /// Unprotected header, plain JSON
    pub(crate) unprotected: Uhd,
    /// "signature" value
    pub(crate) signature: Alg::SigData,
}

impl<Phd: Serialize, Uhd> Signature<Phd, Uhd, Unsigned> {
    pub(crate) fn new_unsigned(protected: Phd, unprotected: Uhd) -> Self {
        Self {
            protected: Json::new(Protected {
                alg: Algorithm::None,
                extra: protected,
            })
            .unwrap(),
            unprotected,
            signature: Empty,
        }
    }
}

impl<Phd, Uhd, Alg> Serialize for Signature<Phd, Uhd, Alg>
where
    Uhd: Serialize,
    Alg: MaybeSigned,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let ser_signature = !is_zst(&self.signature);
        let len = if ser_signature { 2 } else { 1 };
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("protected", &self.protected)?;
        map.serialize_entry("header", &self.unprotected)?;
        if ser_signature {
            map.serialize_entry(
                "signature",
                Base64UrlUnpadded::encode_string(&self.signature),
            )?;
        }
        map.end()
    }
}

fn is_zst<T>(value: &T) -> bool {
    core::mem::size_of::<T>() == 0
}

/// Protected header data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Protected<Phd> {
    /// When we sign, we always set the algorithm
    pub(crate) alg: Algorithm,
    /// Data that
    #[serde(flatten)]
    #[serde(skip_serializing_if = "is_zst")]
    pub(crate) extra: Phd,
}

/// Trait for both signed and unsigned data
pub trait MaybeSigned {
    /// Data representing signature type
    type SigData: Serialize;
}

/// Provide the name of
pub trait AlgorithmMeta {
    const ALGORITHM: Algorithm;
}

/// Trait for all serializable algorithms
pub trait SigningAlg: MaybeSigned + AlgorithmMeta + Sized + Mac + KeyInit {
    fn convert(input: CtOutput<Self>) -> Self::SigData;
}

/// Not yet signed. Note: does not implement serialized
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Unsigned {}

/// Signing algorithm is unknown for e.g., incoming JWEs where type may not be
/// known in advance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnySigning {}

impl MaybeSigned for Unsigned {
    type SigData = Empty;
}

impl<T> MaybeSigned for T
where
    T: Mac,
{
    type SigData = Box<[u8]>;
}

impl AlgorithmMeta for HmacSha256 {
    const ALGORITHM: Algorithm = Algorithm::Hs256;
}
impl AlgorithmMeta for HmacSha384 {
    const ALGORITHM: Algorithm = Algorithm::Hs384;
}
impl AlgorithmMeta for HmacSha512 {
    const ALGORITHM: Algorithm = Algorithm::Hs512;
}

impl<T> SigningAlg for T
where
    T: Mac + AlgorithmMeta + KeyInit,
{
    fn convert(input: CtOutput<Self>) -> Self::SigData {
        input.into_bytes().as_slice().into()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use crate::Empty;

    use super::*;
    use alloc::string::String;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    /// Dummy extra field for testing
    #[derive(Debug, Serialize)]
    struct Extra {
        a: &'static str,
        b: u64,
    }
    const EXTRA: Extra = Extra { a: "foo", b: 100 };

    #[test]
    fn test_protected() {
        // Test serializing extra data as flat
        let input: Protected<Extra> = Protected {
            alg: Algorithm::None,
            extra: EXTRA,
        };
        let expected = json! {{"alg":"none","a":"foo","b":100}};
        assert_eq!(serde_json::to_value(&input).unwrap(), expected);

        // Test no extra data
        let foo: Protected<Empty> = Protected {
            alg: Algorithm::Es256,
            extra: Empty,
        };
        let expected = json! {{"alg":"ES256"}};
        assert_eq!(serde_json::to_value(&foo).unwrap(), expected);
    }

    #[test]
    fn test_signature() {
        type SigTy = Signature<Extra, String, Unsigned>;
        let protected = Protected {
            alg: Algorithm::None,
            extra: EXTRA,
        };
        let sig: SigTy = Signature {
            protected: Json::new(protected).unwrap(),
            unprotected: String::from("bar"),
            signature: Empty,
        };
        let expected = json! {{
            "protected": "eyJhbGciOiJub25lIiwiYSI6ImZvbyIsImIiOjEwMH0",
            "header": "bar",
        }};

        assert_eq!(serde_json::to_value(&sig).unwrap(), expected);
    }
}
