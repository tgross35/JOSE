use alloc::{vec::Vec, string::String};
use base64ct::{Base64UrlUnpadded, Encoding};
use core::fmt;
use hmac::digest::InvalidLength;
use serde::{Deserialize, Serialize};

use crate::{
    private::Sealed,
    signing::{MaybeSigned, Signature, SigningAlg},
    Unsigned,
};

/// Trait for JWS formats. This is sealed because there are only three possible
/// options.
///
/// A format defines the kind of signatures that can be represented. These are:
///
/// - [`Compact`]: The usual Base64-encoded format, which only represents a
///       single signature with protected header data (no unprotected data)
/// - [`Flat`]: A JSON representation of a single signature
/// - [`General`]: A JSON representation allowing more than one signature
pub trait JwsSignable: Sized + Sealed {
    /// Resulting type after signing with an algorithm
    type SignedTy<Alg: MaybeSigned<'static>>;
    /// Resulting type after unsigning
    type UnsignedTy;

    // FIXME: key or payload first? Best to be consistent with rustcrypto
    /// Sign a serializable object
    fn sign_payload<Alg: SigningAlg, T: Serialize>(
        self,
        key: &[u8],
        payload: &T,
    ) -> Result<Self::SignedTy<Alg>, SignError> {
        let payload_ser = serde_json::to_vec(payload)
            .ok()
            .ok_or(SignError::Serialization)?;
        self.sign_bytes(key, &payload_ser)
    }

    /// Sign any raw bytes payload
    fn sign_bytes<Alg: SigningAlg>(
        self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Self::SignedTy<Alg>, SignError> {
        todo!()
    }

    /// Convert any signed & uneditable type into a unsigned editable type
    fn into_unsigned(self) -> Self::UnsignedTy {
        todo!()
    }

    /// Encode self into the default format
    fn encode_string(&self) -> String {
        todo!()
    }
}

pub trait JwsVerifyable<'de>: Sealed {
    fn decode<'a: 'de>(data: &'a str, key: &[u8]) -> Self;
}

/// Errors with signing happen either during serialization or hmac
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum SignError {
    Length(InvalidLength),
    Serialization,
}

impl From<InvalidLength> for SignError {
    fn from(value: InvalidLength) -> Self {
        Self::Length(value)
    }
}

/// Compact format, allows only protected header data
#[derive(Serialize)]
pub struct Compact<Phd, Signing: MaybeSigned> {
    signature: Signature<Phd, Empty, Signing>,
}

impl<Phd, Signed: MaybeSigned> Sealed for Compact<Phd, Signed> {}
// impl<Phd, Signed: MaybeSigned> JwsFormat for Compact<Phd, Signed> {}

impl<Phd, Signing: MaybeSigned> Clone for Compact<Phd, Signing>
where
    Signature<Phd, Empty, Signing>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            signature: self.signature.clone(),
        }
    }
}

impl<Phd, Signing: MaybeSigned> fmt::Debug for Compact<Phd, Signing>
where
    Signature<Phd, Empty, Signing>: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Compact")
            .field("signature", &self.signature)
            .finish()
    }
}

/// Flat format, allows protected and unprotected header data
#[derive(Debug)]
pub struct Flat<Phd, Uhd, Signing: MaybeSigned>(Signature<Phd, Uhd, Signing>);

impl<Phd, Uhd, Signing: MaybeSigned> Serialize for Flat<Phd, Uhd, Signing>
where
    Signature<Phd, Uhd, Signing>: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, Phd, Uhd, Signing: MaybeSigned> Deserialize<'de> for Flat<Phd, Uhd, Signing>
where
    Signature<Phd, Uhd, Signing>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        Ok(Self(Signature::deserialize(deserializer)?))
    }
}

impl<Phd, Uhd, Signing> JwsSignable for Flat<Phd, Uhd, Signing>
where
    Signing: MaybeSigned,
    Phd: Serialize,
    Uhd: Serialize
{
    type SignedTy<Alg: MaybeSigned> = Flat<Phd, Uhd, Alg>;
    type UnsignedTy = Flat<Phd, Uhd, Unsigned>;

    fn sign_bytes<Alg: SigningAlg>(
        self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Self::SignedTy<Alg>, SignError> {
        Ok(Flat(self.0.sign_bytes::<Alg>(key, bytes)?))
    }

    fn into_unsigned(self) -> Self::UnsignedTy {
        Flat(self.0.unsign())
    }

    fn encode_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

impl<'de, Phd, Uhd, Signing> JwsVerifyable<'de> for Flat<Phd, Uhd, Signing>
where
    Signature<Phd, Uhd, Signing>:  Deserialize<'de>,
    Signing: MaybeSigned
{
    fn decode<'a: 'de>(data: &'a str, key: &[u8]) -> Self {
        let x: Self = serde_json::from_str(data).unwrap();
        todo!()
    }
}

impl<Phd, Uhd, Signing: MaybeSigned> Sealed for Flat<Phd, Uhd, Signing> {}

impl<Phd, Uhd, Signing: MaybeSigned> Clone for Flat<Phd, Uhd, Signing>
where
    Signature<Phd, Uhd, Signing>: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

// /// General format, allows >1 signature
// ///
// /// FIXME: only supports a single type
// pub struct General<Phd, Uhd, Signed: MaybeSigned> {
//     signatures: Vec<Signature<Phd, Uhd, Signed>>,
// }

// impl<Phd, Uhd, Signed: MaybeSigned> Sealed for General<Phd,Uhd,Signed> {}
// impl<Phd, Uhd, Signed: MaybeSigned> JwsFormat for General<Phd,Uhd, Signed> {}

/// Representation of no data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Empty;

impl AsRef<[u8]> for Empty {
    /// Unimplemented; needed only to meet our trait bounds
    fn as_ref(&self) -> &[u8] {
        unimplemented!("serde should always skip this field")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::signing::HmacSha256;
    use std::str;

    use super::*;
    use jose_b64::Json;
    use serde_json::{json, Value};

    #[test]
    fn test_flat() {
        let protected = json! {{
            "typ":"JWT",
        }};
        let payload = json! {{
            "iss":"joe",
            "exp":1300819380,
            "http://example.com/is_root":true
        }};
        let expected_sig = "7jHJa4kTe23c-JsCNeHNcAALPyiVB_cbBjCrV_5OcK8";
        let expected = json! {{
            "protected": {"alg": "HS256", "typ": "JWT" },
            "signature": "7jHJa4kTe23c-JsCNeHNcAALPyiVB_cbBjCrV_5OcK8"
        }};
        let sig = Flat(Signature::new_unsigned(protected, Empty));
        let out: Flat<Value, Empty, HmacSha256> = sig
            .sign_payload::<HmacSha256, _>("hi".as_bytes(), &payload)
            .unwrap();
        assert_eq!(expected_sig, out.0.signature.encode_string());
        assert_eq!(expected, serde_json::to_value(&out).unwrap());
        std::dbg!(out.encode_string());
        std::dbg!(serde_json::from_str::<Flat<Value, Empty, HmacSha256>>(&out.encode_string()));
    }
}
