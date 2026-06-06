//! Shared newtypes used at the kernel ↔ PAL boundary.
//! Newtypes prevent confusing parameters of the same primitive type at
//! the API surface. Today the NSC veneers take bare `u32` for enclave
//! IDs — that's the C ABI, which is frozen. **Inside** the Secure
//! kernel, after arg-validation, IDs are wrapped in these newtypes so
//! the rest of the call chain is type-safe.

/// Enclave identifier — NS-supplied u32 after arg-validation.
/// type-state markers (`SecurityState`, `EnclaveHandle<S>`)
/// wrap this newtype to encode lifecycle progress in the type system.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct EnclaveId(pub u32);

/// Block address within EFBC (Secure alias).
/// Distinguishes from `EnclaveId` to prevent argument transposition at
/// kernel ↔ PAL boundary sites.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct BlockAddr(pub u32);

/// SHA-256 digest used for chained measurement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Measurement(pub [u8; 32]);
