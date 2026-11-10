//! Console UART reception core: RX buffer + exclusive ownership. No MMIO,
//! host-tested. The boot crate feeds `rx_push` from the UART IRQ and calls
//! the rest from SVC/veneer context inside a critical section.

pub const RX_CAPACITY: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Owner {
    /// The NS host: owner whenever no enclave is.
    Ns,
    Enclave(u32),
}

pub struct ConsoleUart {
    buf: [u8; RX_CAPACITY],
    head: usize,
    len: usize,
    overflow: u32,
    owner: Owner,
}

/// `claim` on a UART another enclave owns.
#[derive(Debug, PartialEq, Eq)]
pub struct Busy;

/// `release` by an enclave that does not own the UART.
#[derive(Debug, PartialEq, Eq)]
pub struct NotOwner;

impl ConsoleUart {
    pub const fn new() -> Self {
        Self {
            buf: [0; RX_CAPACITY],
            head: 0,
            len: 0,
            overflow: 0,
            owner: Owner::Ns,
        }
    }

    pub fn claim(&mut self, id: u32) -> Result<(), Busy> {
        if let Owner::Enclave(other) = self.owner {
            if other != id {
                return Err(Busy);
            }
        }
        self.handover(Owner::Enclave(id));
        Ok(())
    }

    pub fn release(&mut self, id: u32) -> Result<(), NotOwner> {
        if self.owner != Owner::Enclave(id) {
            return Err(NotOwner);
        }
        self.handover(Owner::Ns);
        Ok(())
    }

    /// Enclave `id` terminated or faulted: automatic release if it owned the UART.
    pub fn owner_gone(&mut self, id: u32) {
        let _ = self.release(id);
    }

    /// A new owner never sees bytes typed for the previous one.
    fn handover(&mut self, to: Owner) {
        if to != self.owner {
            self.owner = to;
            self.len = 0;
            self.overflow = 0;
        }
    }

    /// Full buffer drops the newest byte: what is queued stays in order.
    pub fn rx_push(&mut self, byte: u8) {
        if self.len == RX_CAPACITY {
            self.overflow = self.overflow.saturating_add(1);
            return;
        }
        self.buf[(self.head + self.len) % RX_CAPACITY] = byte;
        self.len += 1;
    }

    pub fn getc(&mut self, caller: Owner) -> Option<u8> {
        if caller != self.owner || self.len == 0 {
            return None;
        }
        let b = self.buf[self.head];
        self.head = (self.head + 1) % RX_CAPACITY;
        self.len -= 1;
        Some(b)
    }

    pub fn overflow(&self, caller: Owner) -> Option<u32> {
        (caller == self.owner).then_some(self.overflow)
    }

    pub fn owner(&self) -> Owner {
        self.owner
    }

    /// TX gate between enclaves only: NS and kernel logs always pass.
    pub fn may_transmit(&self, caller: Owner) -> bool {
        caller == Owner::Ns || caller == self.owner
    }
}

#[cfg(test)]
#[path = "uart_rx_tests.rs"]
mod tests;
