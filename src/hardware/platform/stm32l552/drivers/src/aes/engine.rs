// Author: Salvatore Bramante <salvatore.bramante@imtlucca.it>

//! Common `AesEngine` trait shared by `AesEmulated` (software) and
//! `AesHardware` (L562 HW peripheral).

/// Common interface for AES engines (Hardware and Emulated).
pub trait AesEngine {
    /// Only AES-128 is guaranteed to be supported by both implementations;
    /// `iv` is consumed by CTR-style callers (see `AesAdapter`).
    fn init(&mut self, key: &[u8], iv: Option<&[u8]>);

    fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]);

    fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]);
}
