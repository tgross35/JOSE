use alloc::vec::Vec;
use base64ct::{Base64UrlUnpadded, Encoding};
use core::fmt;
use hmac::digest::InvalidLength;
use serde::{Deserialize, Serialize};

use crate::{
    private::Sealed,
    signing::{MaybeSigned, Signature, SigningAlg},
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
pub trait JwsSignable: Sealed {
    /// Resulting type after signing with an algorithm
    type SignedTy<Alg: MaybeSigned>;

    // FIXME: key or payload first? Best to be consistent with rustcrypto
    /// Sign a serializable object
    fn sign_payload<Alg: SigningAlg, T: Serialize>(
        self,key: &[u8],
        payload: &T,
    ) -> Result<Self::SignedTy<Alg>, SignError>
    where
        Self: Sized,
    {
        let payload_ser = serde_json::to_vec(payload)
            .ok()
            .ok_or(SignError::Serialization)?;
        self.sign_bytes(key, &payload_ser)
    }

    /// Sign any raw bytes payload
    fn sign_bytes<Alg: SigningAlg>(self, key: &[u8],bytes: &[u8]) -> Result<Self::SignedTy<Alg>, SignError>
    where
        Self: Sized,
    {
        todo!()
    }
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
// #[derive(Debug)]
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

impl<Phd, Uhd, Signing> JwsSignable for Flat<Phd, Uhd, Signing>
where
    Signing: MaybeSigned,
    Phd: Serialize,
{
    type SignedTy<Alg: MaybeSigned> = Flat<Phd, Uhd, Alg>;

    fn sign_bytes<Alg: SigningAlg>(
        mut self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Self::SignedTy<Alg>, SignError> {
        self.0.protected.update(|p| p.alg = Alg::ALGORITHM);
        let mut mac = <Alg as hmac::Mac>::new_from_slice(key)?;

        let protected_ser = serde_json::to_vec(&self.0.protected)
            .ok()
            .ok_or(SignError::Serialization)?;
        // TODO we're serializing the json and not b64 here
        std::dbg!(std::str::from_utf8(&self.0.protected.as_ref()));
        // std::dbg!(std::str::from_utf8(&protected_ser));
        mac.update(self.0.protected.as_ref());

        std::dbg!(std::str::from_utf8(bytes));
        mac.update(std::dbg!(&Base64UrlUnpadded::encode_string(bytes)).as_bytes());
        let signature = Alg::convert(mac.finalize()).into();

        Ok(Flat(Signature {
            protected: self.0.protected,
            unprotected: self.0.unprotected,
            signature,
        }))
    }
}
extern crate std;

impl<Phd, Uhd, Signing: MaybeSigned> Sealed for Flat<Phd, Uhd, Signing> {}

impl<Phd, Uhd, Signing: MaybeSigned> Clone for Flat<Phd, Uhd, Signing>
where
    Signature<Phd, Uhd, Signing>: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Phd, Uhd, Signing: MaybeSigned> fmt::Debug for Flat<Phd, Uhd, Signing>
where
    Signature<Phd, Uhd, Signing>: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Flat").field(&self.0).finish()
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
    fn as_ref(&self) -> &[u8] {
        unimplemented!()
        // &[]
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::signing::HmacSha256;

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
        let sig = Flat(Signature::new_unsigned(protected, Empty));
        std::dbg!(&sig);
        let out: Flat<Value, Empty, HmacSha256> =
            sig.sign_payload::<HmacSha256, _>("hi".as_bytes(), &payload).unwrap();
        std::dbg!(&out);
        std::dbg!(serde_json::to_string(&out).unwrap());
    }
}
