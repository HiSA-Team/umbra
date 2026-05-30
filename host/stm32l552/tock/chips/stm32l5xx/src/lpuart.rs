//! LPUART1 driver for STM32L5xx (NS alias), implementing the Tock `Transmit`
//! HIL via polled busy-wait writes. RX is stubbed.
//!
//! Target wiring on NUCLEO-L552ZE-Q VCP:
//!   - Peripheral: LPUART1, NS base 0x40008000 (Secure alias 0x50008000)
//!   - TX: PG7 / AF8; RX: PG8 / AF8
//!   - Clock source: LSE (32.768 kHz external crystal), selected via CCIPR1
//!   - 9600 baud → BRR = 256 X 32768 / 9600 ≈ 873 = 0x369
//!     (LPUART BRR formula differs from USART; see RM0438 §47.5.3.)
//!
//! Per RM0438 §47.5.2, CR1.UE must be 0 while writing BRR. `init()` enforces
//! that ordering: clear UE → write BRR → set TE → set UE.

use core::cell::Cell;
use kernel::hil::uart::{Configure, Parameters, Receive, ReceiveClient, Transmit, TransmitClient};
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::registers::{register_bitfields, register_structs, ReadWrite};
use kernel::utilities::StaticRef;
use kernel::ErrorCode;

pub const LPUART1_BASE: StaticRef<LpuartRegisters> =
    unsafe { StaticRef::new(0x4000_8000 as *const LpuartRegisters) };

register_structs! {
    pub LpuartRegisters {
        (0x00 => cr1: ReadWrite<u32, CR1::Register>),
        (0x04 => cr2: ReadWrite<u32>),
        (0x08 => cr3: ReadWrite<u32>),
        (0x0C => brr: ReadWrite<u32, BRR::Register>),
        // GTPR (0x10) and RTOR (0x14) are reserved in LPUART.
        (0x10 => _reserved0),
        (0x14 => _reserved1),
        (0x18 => rqr: ReadWrite<u32>),
        (0x1C => isr: ReadWrite<u32, ISR::Register>),
        (0x20 => icr: ReadWrite<u32>),
        (0x24 => rdr: ReadWrite<u32>),
        (0x28 => tdr: ReadWrite<u32, TDR::Register>),
        (0x2C => presc: ReadWrite<u32>),
        (0x30 => @END),
    }
}

register_bitfields![u32,
    CR1 [
        UE    OFFSET(0) NUMBITS(1) [],
        RE    OFFSET(2) NUMBITS(1) [],
        TE    OFFSET(3) NUMBITS(1) [],
        TCIE  OFFSET(6) NUMBITS(1) [],
        TXEIE OFFSET(7) NUMBITS(1) []
    ],
    BRR [
        BRR OFFSET(0) NUMBITS(20) []
    ],
    ISR [
        TC  OFFSET(6) NUMBITS(1) [],
        TXE OFFSET(7) NUMBITS(1) []
    ],
    TDR [
        TDR OFFSET(0) NUMBITS(9) []
    ]
];

#[derive(Copy, Clone, PartialEq)]
enum TxState {
    Idle,
    Transmitting,
}

pub struct Lpuart1<'a> {
    regs: StaticRef<LpuartRegisters>,
    tx_client: OptionalCell<&'a dyn TransmitClient>,
    tx_state: Cell<TxState>,
}

impl<'a> Lpuart1<'a> {
    pub const fn new() -> Self {
        Self {
            regs: LPUART1_BASE,
            tx_client: OptionalCell::empty(),
            tx_state: Cell::new(TxState::Idle),
        }
    }

    /// Configure LPUART1 for 9600 baud on LSE. Preconditions: PWR + LPUART1
    /// + GPIOG clocks gated on, LSE running, CCIPR1.LPUART1SEL set to LSE,
    /// PG7/PG8 in AF8.
    pub fn init(&self) {
        let regs = &*self.regs;
        regs.cr1.modify(CR1::UE::CLEAR);
        regs.brr.write(BRR::BRR.val(0x369));
        regs.cr1.modify(CR1::TE::SET);
        regs.cr1.modify(CR1::UE::SET);
    }

    /// Blocking write of a single byte. Polls ISR.TXE before touching TDR.
    pub fn write_byte(&self, byte: u8) {
        while !self.regs.isr.is_set(ISR::TXE) {}
        self.regs.tdr.write(TDR::TDR.val(byte as u32));
    }

    /// Bypasses HIL `TxState` tracking — intended for early boot tracing
    /// before the Tock kernel takes over the UART. Interleaving with
    /// `transmit_buffer` will corrupt output.
    pub fn write_str(&self, s: &str) {
        for b in s.bytes() {
            self.write_byte(b);
        }
    }
}

impl<'a> Transmit<'a> for Lpuart1<'a> {
    fn set_transmit_client(&self, client: &'a dyn TransmitClient) {
        self.tx_client.set(client);
    }

    /// Polled write. Spins on TXE per byte, then invokes
    /// `transmitted_buffer` synchronously before returning (no IRQ, no
    /// deferred callback).
    fn transmit_buffer(
        &self,
        tx_buffer: &'static mut [u8],
        tx_len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if self.tx_state.get() != TxState::Idle {
            return Err((ErrorCode::BUSY, tx_buffer));
        }
        if tx_len > tx_buffer.len() {
            return Err((ErrorCode::SIZE, tx_buffer));
        }

        self.tx_state.set(TxState::Transmitting);
        for i in 0..tx_len {
            self.write_byte(tx_buffer[i]);
        }
        self.tx_state.set(TxState::Idle);

        self.tx_client.map(|client| {
            client.transmitted_buffer(tx_buffer, tx_len, Ok(()));
        });

        Ok(())
    }

    fn transmit_word(&self, _word: u32) -> Result<(), ErrorCode> {
        Err(ErrorCode::FAIL)
    }

    fn transmit_abort(&self) -> Result<(), ErrorCode> {
        if self.tx_state.get() == TxState::Idle {
            Ok(())
        } else {
            Err(ErrorCode::FAIL)
        }
    }
}

impl<'a> Receive<'a> for Lpuart1<'a> {
    fn set_receive_client(&self, _client: &'a dyn ReceiveClient) {}

    fn receive_buffer(
        &self,
        rx_buffer: &'static mut [u8],
        _rx_len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        Err((ErrorCode::NOSUPPORT, rx_buffer))
    }

    fn receive_word(&self) -> Result<(), ErrorCode> {
        Err(ErrorCode::NOSUPPORT)
    }

    fn receive_abort(&self) -> Result<(), ErrorCode> {
        Ok(())
    }
}

/// Stub `Configure` so the kernel's blanket `Uart` impl applies. Baud is
/// hardwired in `Lpuart1::init` — runtime reconfiguration is unsupported.
impl Configure for Lpuart1<'_> {
    fn configure(&self, _params: Parameters) -> Result<(), ErrorCode> {
        Ok(())
    }
}
