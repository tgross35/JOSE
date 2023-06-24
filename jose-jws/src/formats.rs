use alloc::vec::Vec;
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
pub trait JwsSignable<Alg: SigningAlg, SignedTy>: Sealed {
    fn sign_payload<T: Serialize>(self, payload: &T) -> Result<SignedTy, SignError>
    where
        Self: Sized,
    {
        todo!()
    }
}

/// Errors with signing happen either during serialization or hmac
#[non_exhaustive]
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
#[derive(Serialize)]
pub struct Flat<Phd, Uhd, Signing: MaybeSigned>(Signature<Phd, Uhd, Signing>);

impl<Phd, Uhd, Signing, Alg> JwsSignable<Alg, Flat<Phd, Uhd, Alg>> for Flat<Phd, Uhd, Signing>
where
    Signing: MaybeSigned,
    Alg: SigningAlg,
{
    fn sign_payload<T: Serialize>(self, payload: &T) -> Result<Flat<Phd, Uhd, Alg>, SignError> {
        let protected_ser = serde_json::to_vec(&self.0.protected)
            .ok()
            .ok_or(SignError::Serialization)?;
        let mut mac = <Alg as hmac::Mac>::new_from_slice(&protected_ser)?;
        let payload_ser = serde_json::to_vec(payload)
            .ok()
            .ok_or(SignError::Serialization)?;
        mac.update(&payload_ser);
        let signature = Alg::convert(mac.finalize());

        Ok(Flat(Signature {
            protected: self.0.protected,
            header: self.0.header,
            signature,
        }))
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

#[cfg(test)]
mod tests {
    #[test]
    fn test_compact() {}
}
