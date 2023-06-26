// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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

use serde::{Deserialize, Serialize};

/// Possible key types, as defined in [RFC7518]
/// section 6.1. Used for JWK `kty` parameter.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeyType {
    /// Elliptic Curve (NIST DSS, Recommended+)
    Ec,
    /// RSA (RFC3447, Required)
    Rsa,
    /// Octet sequence, used to represent symmetric keys (Required)
    #[serde(rename = "oct")]
    Oct,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::prelude::rust_2021::*;
    use std::vec;

    use super::*;

    #[test]
    fn test_signing_roundtrip() {
        use Signing as S;

        let input = vec![
            S::EdDsa,
            S::Es256,
            S::Es256K,
            S::Es384,
            S::Es512,
            S::Hs256,
            S::Hs384,
            S::Hs512,
            S::Ps256,
            S::Ps384,
            S::Ps512,
            S::Rs256,
            S::Rs384,
            S::Rs512,
            S::None,
        ];
        let ser = serde_json::to_string(&input).expect("serialization failed");

        assert_eq!(
            ser,
            r#"["EdDSA","ES256","ES256K","ES384","ES512","HS256","HS384","HS512","PS256","PS384","PS512","RS256","RS384","RS512","none"]"#
        );

        assert_eq!(
            serde_json::from_str::<Vec<Signing>>(&ser).expect("deserialization failed"),
            input
        );
    }
}
