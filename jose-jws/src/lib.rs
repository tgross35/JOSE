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

use formats::JwsFormat;
pub use formats::{Empty, Compact};
use jose_b64::{Json, Bytes};
use serde::{Deserialize, Serialize};
pub use signing::Unsigned;

extern crate alloc;

mod private;
mod formats;
mod signing;

/// A JSON Web Signature representation with statically typed format
/// 
/// A JWS has three parts:
/// 
/// - A header
/// - A payload, represented as type `T`
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Jws<T, Fmt: JwsFormat = Compact<Empty, Unsigned>> {
    payload: T,
    #[serde(flatten)]
    data: Fmt,
}

#[cfg(test)]
mod tests {
    extern crate std;
    use crate::signing::{Signature, Protected};

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
