
pub const KEY_SIZE: usize = 32;

#[derive(Copy, Clone)]
pub struct Key {
    pub value: [u8; KEY_SIZE],
}

impl Key {
    pub fn new(value: [u8; KEY_SIZE]) -> Self {
        Self { value }
    }
    
    pub fn zero() -> Self {
        Self { value: [0; KEY_SIZE] }
    }
}

pub const MAX_KEYS: usize = 8;

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
