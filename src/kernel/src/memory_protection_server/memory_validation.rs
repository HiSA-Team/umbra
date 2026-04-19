use crate::key_storage_server::key_generator::KeyGenerator;
use crate::key_storage_server::key_store::Key;

pub struct MemoryValidator;

impl MemoryValidator {
    /// Validates a single block by computing its Hash/HMAC and comparing with expected value.
    pub fn validate_block(
        generator: &mut KeyGenerator,
        data: &[u8],
        expected_measurement: &Key
    ) -> bool {
        // Using a zero key to derive a measurement from the data block
        let base_key = Key::zero();
        if let Ok(computed) = generator.derive_key(&base_key, data) {
             generator.verify_measurement(&computed.value, &expected_measurement.value)
        } else {
            false
        }
    }

}
