// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
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
#![allow(unused)]

pub use formats::{Compact, Empty};
use formats::{Flat, JwsSignable};
use jose_b64::{B64Bytes, Json};
use serde::{Deserialize, Serialize};
use signing::HmacSha256;
pub use signing::Unsigned;

extern crate alloc;

mod formats;
mod private;
mod signing;

/// A JSON Web Signature representation with statically typed format
///
/// A JWS has three parts:
///
/// - A header
/// - A payload, represented as type `T`
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Jws<T, Fmt> {
    // pub struct Jws<T, Fmt: JwsFormat = Compact<Empty, Unsigned>> {
    payload: T,
    #[serde(flatten)]
    data: Fmt,
}

/// Default compact form, standard JOSE header
pub type JwsCompact<T> = Jws<T, Compact<JoseHeader, HmacSha256>>;

/// Default flat form
pub type JwsFlat<T> = Jws<T, Flat<JoseHeader, Empty, HmacSha256>>;

/// Standard JOSE header types
#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoseHeader {}

#[cfg(test)]
mod tests {
    extern crate std;
    use crate::signing::{Protected, Signature};

    use super::*;

    #[test]
    fn test_compact() {
        // let foo = Jws {
        //     payload: "hello world",
        //     data: Compact {
        //         signature: Signature {
        //             protected: Protected {
        //                 alg: None,
        //                 extra: (),
        //             },
        //             unprotected: Unprotected{ extra: () },
        //             signature: Unsigned{},
        //         }
        //     },
        // };

        // std::dbg!(serde_json::to_string(&foo));
    }
}
