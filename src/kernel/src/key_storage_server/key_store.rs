// `Key` / `KEY_SIZE` now live in the verifiable `umbra-rot-core` crate
// re-exported here so the kernel and the RoT proofs share one
// type and every `key_store::{Key, KEY_SIZE}` call site is unchanged.
pub use umbra_rot_core::{Key, KEY_SIZE};

pub use crate::common::ess::MAX_KEYS;

pub struct KeyStore {
    pub keys: [Option<Key>; MAX_KEYS],
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: [None; MAX_KEYS],
        }
    }

    pub fn get_key(&self, index: usize) -> Option<Key> {
        if index >= MAX_KEYS {
            return None;
        }
        self.keys[index]
    }
}
