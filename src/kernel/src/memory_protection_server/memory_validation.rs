use crate::key_storage_server::key_generator::KeyGenerator;
use crate::key_storage_server::key_store::Key;

pub struct MemoryValidator;

impl MemoryValidator {
    /// Validates a single block by computing its measurement and comparing with
    /// the expected value. Delegates to the verifiable `umbra-rot-core`
    /// validator (proved sound — T4: a `true` result implies the derived
    /// measurement equals `expected_measurement`).
    pub fn validate_block(
        generator: &mut KeyGenerator,
        data: &[u8],
        expected_measurement: &Key,
    ) -> bool {
        generator.validate_block(data, expected_measurement)
    }
}
