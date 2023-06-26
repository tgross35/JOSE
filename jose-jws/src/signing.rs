use core::{convert::Infallible, fmt::Debug};

use alloc::{boxed::Box, vec::Vec};
use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{
    digest::{CtOutput, InvalidLength, KeyInit},
    Hmac, Mac,
};
use jose_b64::{B64Bytes, Json};
use jose_jwa::Signing;
use serde::{ser::SerializeMap, Deserialize, Serialize};

use crate::{formats::SignError, private::Sealed, Empty};

pub type HmacSha256 = Hmac<sha2::Sha256>;
pub type HmacSha384 = Hmac<sha2::Sha384>;
pub type HmacSha512 = Hmac<sha2::Sha512>;

/// Trait for both signed and unsigned data
pub trait MaybeSigned<'de> {
    /// Data representing signature type
    type SigData: Serialize + Deserialize<'de> + AsRef<[u8]> + Debug;
}

/// Marker trait indicating data can be edited. We use this to forbid editing of
/// signed data
pub trait Mutable: Sealed {}

/// Provide the enum variant of the algorithm
///
/// This trait is separate from [`SigningAlg`] so we can derive `SigningAlg` but
/// manually match the enum variant
pub trait AlgorithmMeta {
    const ALGORITHM: Signing;
}

/// Trait for all serializable algorithms
pub trait SigningAlg: MaybeSigned<'static> + AlgorithmMeta + Sized + Mac + KeyInit {
    /// Convert a Mac's output to the correct signature data
    fn convert(input: CtOutput<Self>) -> Self::SigData;
}

/// Marker type implementing data that has not yet signed.
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
    const ALGORITHM: Signing = Signing::Hs256;
}
impl AlgorithmMeta for HmacSha384 {
    const ALGORITHM: Signing = Signing::Hs384;
}
impl AlgorithmMeta for HmacSha512 {
    const ALGORITHM: Signing = Signing::Hs512;
}

/// Blanket implementation for all HMacs with a defined algorithm
impl<T> SigningAlg for T
where
    T: Mac + AlgorithmMeta + KeyInit,
{
    fn convert(input: CtOutput<Self>) -> Self::SigData {
        input.into_bytes().as_slice().into()
    }
}

/// A single signature contains protected data, unprotected data, and then the
/// signature itself. The signature is the MAC of the payload plus the protected
/// header data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature<Phd, Uhd, Signing: MaybeSigned> {
    /// Protected header, base64 serialized
    pub(crate) protected: Protected<Phd>,
    /// Unprotected header, plain JSON
    #[serde(rename = "header")]
    #[serde(skip_serializing_if = "is_zst")]
    pub(crate) unprotected: Uhd,
    /// "signature" value
    #[serde(skip_serializing_if = "is_zst")]
    pub(crate) signature: B64Bytes<Signing::SigData>,
}

impl<Phd, Uhd, Signing> Signature<Phd, Uhd, Signing>
where
    Signing: MaybeSigned,
    Phd: Serialize,
{
    /// Update `signature` with the Mac-produced signature of our protected
    /// header and a bytes payload
    ///
    /// Process (as in [RFC7515 Section 5.1]):
    ///
    /// 1. Compute the header as B64URL(UTF8(Protected Header))
    /// 2. Compute the payload as B64URL(payload)
    /// 3. Calculate the signature of `"{header}.{payload}"` with the provided key
    ///
    /// [RFC7515 Section 5.1]: https://www.rfc-editor.org/rfc/rfc7515#section-5.1
    pub(crate) fn sign_bytes<Alg: SigningAlg>(
        mut self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Signature<Phd, Uhd, Alg>, SignError> {
        self.protected.alg = Alg::ALGORITHM;
        let mut mac = <Alg as Mac>::new_from_slice(key)?;
        let header = serde_json::to_vec(&self.protected)
            .ok()
            .ok_or(SignError::Serialization)?;

        mac.update(Base64UrlUnpadded::encode_string(&header).as_bytes());
        mac.update(b".");
        mac.update(Base64UrlUnpadded::encode_string(bytes).as_bytes());
        Ok(Signature {
            protected: self.protected,
            unprotected: self.unprotected,
            signature: Alg::convert(mac.finalize()).into(),
        })
    }

    /// Turn into an unsigned signature
    pub(crate) fn unsign(mut self) -> Signature<Phd, Uhd, Unsigned> {
        self.protected.alg = Signing::None;
        Signature {
            protected: self.protected,
            unprotected: self.unprotected,
            signature: Empty.into(),
        }
    }
}

impl<Phd: Serialize, Uhd> Signature<Phd, Uhd, Unsigned> {
    ///
    pub(crate) fn new_unsigned(protected: Phd, unprotected: Uhd) -> Self {
        Self {
            protected: Protected {
                alg: Signing::None,
                extra: protected,
            },
            unprotected,
            signature: Empty.into(),
        }
    }
}

/// Helper for Serde
fn is_zst<T>(value: &T) -> bool {
    core::mem::size_of::<T>() == 0
}

/// Protected header data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Protected<Phd> {
    /// When we sign, we always set the algorithm
    pub(crate) alg: Signing,
    /// Data that
    #[serde(flatten)]
    #[serde(skip_serializing_if = "is_zst")]
    pub(crate) extra: Phd,
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
            alg: Signing::None,
            extra: EXTRA,
        };
        let expected = json! {{"alg":"none","a":"foo","b":100}};
        assert_eq!(serde_json::to_value(input).unwrap(), expected);

        // Test no extra data
        let foo: Protected<Empty> = Protected {
            alg: Signing::Es256,
            extra: Empty,
        };
        let expected = json! {{"alg":"ES256"}};
        assert_eq!(serde_json::to_value(foo).unwrap(), expected);
    }

    #[test]
    fn test_signature() {
        type SigTy = Signature<Extra, String, Unsigned>;
        let sig: SigTy = Signature::new_unsigned(EXTRA, String::from("bar"));

        let expected = json! {{
            "protected": {
                "alg": "none",
                "a": "foo",
                "b": 100
            },
            "header": "bar",
        }};

        assert_eq!(serde_json::to_value(sig).unwrap(), expected);
    }
}
