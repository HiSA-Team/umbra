//! CRYP1 driver for STM32N657
//! Base: 0x54020800 (Secure) / 0x44020800 (NS).
//! Hardware AES: 11 cycles per 16-byte block.
//!
//! Skeleton only — methods below are stubs pending a full RM0486 §27 port.

pub trait AesEngine {
    fn init(&mut self, key: &[u8], iv: Option<&[u8]>);
    fn encrypt_block(&mut self, input: &[u8], output: &mut [u8]);
    fn decrypt_block(&mut self, input: &[u8], output: &mut [u8]);
}

pub struct CrypHardware;

impl CrypHardware {
    pub fn new() -> Self { CrypHardware }
}

impl AesEngine for CrypHardware {
    fn init(&mut self, _key: &[u8], _iv: Option<&[u8]>) {}
    fn encrypt_block(&mut self, _input: &[u8], _output: &mut [u8]) {}
    fn decrypt_block(&mut self, _input: &[u8], _output: &mut [u8]) {}
}
