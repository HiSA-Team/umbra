//! Platform abstraction layer — re-exported from `umbra_api::platform`.
//! moved the trait definition to the leaf umbra-api
//! crate. This module remains as a backwards-compatibility shim so
//! existing `use kernel::platform::PlatformBoot;` call sites keep
//! compiling. New code should import directly from `umbra_api::PlatformBoot`.

pub use umbra_api::PlatformBoot;
