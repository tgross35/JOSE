use alloc::vec::Vec;
use serde::{Serialize, Deserialize};
use core::fmt;

use crate::{private::Sealed, signing::{MaybeSigned, Signature}};

/// Trait for JWS formats. This is sealed because there are only three possible
/// options.
/// 
/// A format defines the kind of signatures that can be represented. These are:
/// 
/// - [`Compact`]: The usual Base64-encoded format, which only represents a
///       single signature with protected header data (no unprotected data)
/// - [`Flat`]: A JSON representation of a single signature
/// - [`General`]: A JSON representation allowing more than one signature
pub trait JwsFormat: Sealed {}

/// Compact format, allows only protected header data
// #[derive(Serialize, Deserialize)]
pub struct Compact<Phd, Signed: MaybeSigned> {
    signature: Signature<Phd, Empty, Signed>,
}

// impl<Phd, Signed: MaybeSigned+Clone> Clone for Compact<Phd, Signed> {
//     fn clone(&self) -> Self {
//         Self { signature: self.signature.clone() }
//     }
// }

// impl<Phd, Signed: MaybeSigned+fmt::Debug> fmt::Debug for Compact<Phd, Signed> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         f.debug_struct("Compact").field("signature", &self.signature).finish()
//     }
// }


impl<Phd, Signed: MaybeSigned> Sealed for Compact<Phd, Signed> {}
impl<Phd, Signed: MaybeSigned> JwsFormat for Compact<Phd, Signed> {}

// /// Flat format, allows protected and unprotected header data
// pub struct Flat<Phd, Uhd, Signed: MaybeSigned> {
//     signature: Signature<Phd, Uhd, Signed>,
// }

// impl<Phd, Uhd, Signed: MaybeSigned> Sealed for Flat<Phd,Uhd,Signed> {}
// impl<Phd, Uhd, Signed: MaybeSigned> JwsFormat for Flat<Phd,Uhd, Signed> {}

// /// General format, allows >1 signature
// /// 
// /// FIXME: only supports a single type
// pub struct General<Phd, Uhd, Signed: MaybeSigned> {
//     signatures: Vec<Signature<Phd, Uhd, Signed>>,
// }

// impl<Phd, Uhd, Signed: MaybeSigned> Sealed for General<Phd,Uhd,Signed> {}
// impl<Phd, Uhd, Signed: MaybeSigned> JwsFormat for General<Phd,Uhd, Signed> {}

/// Representation of no data
pub type Empty = ();
