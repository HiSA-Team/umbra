pub trait CryptoEngine {
    fn hmac(&mut self, key: &[u8], data: &[u8], output: &mut [u8]) -> Result<(), ()>;
    fn hash(&mut self, data: &[u8], output: &mut [u8]) -> Result<(), ()>;
    fn aes_decrypt(&mut self, key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), ()>;
}
