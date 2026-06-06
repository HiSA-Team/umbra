//! `CryptoEngine` trait — re-exported from `umbra_api::crypto`.
//! moved the definition to the leaf `umbra-api` crate
//! to break the kernel↔driver dep cycle. This module remains as a
//! backwards-compatibility shim so existing `use kernel::key_storage_server::crypto::CryptoEngine;`
//! call sites in `crypto_impl.rs`, `key_derivation.rs`, etc. keep compiling.
//! New code should import directly from `umbra_api::CryptoEngine`.

pub use umbra_api::CryptoEngine;
