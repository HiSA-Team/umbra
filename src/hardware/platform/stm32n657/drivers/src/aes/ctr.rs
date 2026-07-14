//! Hardware AES-128 path: ECB block ops + native CTR override.
//! Holds `impl AesEngine for AesHardware`. The ECB block primitives
//! (`encrypt_block` / `decrypt_block`) call into `cryp.rs::process_block`;
//! `ctr_xform` overrides the trait default by reconfiguring CRYP to
//! ALGOMODE=0x6 (native CTR) so the peripheral does keystream + XOR +
//! counter-increment internally — see Section B.X HPDMA post-mortem in
//! `cryp.rs` for the rejected DMA path.

use peripheral_regs::MmioAccess;

use super::ecb::AesEngine;
use super::keyreg::AesHardware;

impl<M: MmioAccess> AesEngine for AesHardware<M> {
    fn init(&mut self, _key: &[u8], _iv: Option<&[u8]>) {
        // DHUK shared-key path (issue #45): CRYP is keyed by the boot-time
        // SAES share (`dhuk_provision::provision_and_share_enc_key`), NOT by a
        // software key load. The passed key is therefore vestigial and
        // intentionally ignored — `init` only puts CRYP back into ECB-shared
        // mode (no KEYRx writes). This REQUIRES the SAES share to have already
        // run (CRYP KEYVALID set); the orchestrator runs first in init_kernel.
        self.cryp.configure_ecb_shared();
    }

    fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        self.cryp.process_block(input, output);
    }

    fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        // Intentional: CTR is symmetric, runtime never calls decrypt_block.
        // boot_tests uses AesEmulated for math sanity.
        self.cryp.process_block(input, output);
    }

    /// Native HW CTR via DMA — the revived Phase B.X path. The reverted "DMA debug
    /// unresolved" wall was the RISAF CID-1 filter, not the crypto: the AES path is
    /// BIDIRECTIONAL (mem→CRYP_DIN + CRYP_DOUT→mem), BOTH channels cross AXISRAM, and the
    /// RISAF admits only CID 1 — without presenting it the RISAF silently dropped the
    /// DOUT→mem writes, leaving the output == input (the exact B.X symptom). Streams
    /// `data` in place over two HPDMA1 channels, both presenting CID 1. Whole 16-byte
    /// blocks only; a sub-block tail is left untouched.
    ///
    /// Non-arm targets fall back to the AesEngine trait's software default — `AesHardware`
    /// is device-only, host tests use `AesEmulated`. HPDMA word transfers need word-aligned
    /// buffers; the device callers (the 256 B enclave block and the word-aligned checkpoint
    /// SNAP) satisfy this.
    #[cfg(target_arch = "arm")]
    fn ctr_xform(&mut self, iv: &[u8; 16], data: &mut [u8]) {
        use crate::hpdma::{self, Hpdma1};
        const CRYP_DIN_ADDR: u32 = 0x5402_0808;
        const CRYP_DOUT_ADDR: u32 = 0x5402_080C;
        const REQ_CRYP_IN: u8 = 9; // cryp_in_dma (RM §18 request table)
        const REQ_CRYP_OUT: u8 = 10; // cryp_out_dma
        const CH_IN: u8 = 0;
        const CH_OUT: u8 = 1;

        let byte_count = ((data.len() / 16) * 16) as u32; // whole blocks only
        if byte_count == 0 {
            return;
        }

        hpdma::enable_clock(); // self-sufficient — no boot-order dependency
        self.cryp.configure_ctr_shared_for_dma(iv);
        self.cryp.enable_dma();

        let dma = Hpdma1::new();
        // Present CID 1 on BOTH channels — the fix B.X lacked.
        dma.set_channel_secure(CH_IN);
        dma.set_channel_secure(CH_OUT);
        dma.reset_channel(CH_IN);
        dma.reset_channel(CH_OUT);
        dma.configure_mem_to_periph(
            CH_IN,
            data.as_ptr() as u32,
            CRYP_DIN_ADDR,
            byte_count,
            REQ_CRYP_IN,
        );
        dma.configure_periph_to_mem(
            CH_OUT,
            CRYP_DOUT_ADDR,
            data.as_mut_ptr() as u32,
            byte_count,
            REQ_CRYP_OUT,
        );

        // In-place: push the plaintext out of D-cache so the DMA reads it from memory.
        hpdma::dcache_clean_range(data.as_ptr() as usize, byte_count as usize);

        // Arm the drain (OUT) before the feed (IN) so it's ready for the first block.
        dma.enable_channel(CH_OUT);
        dma.enable_channel(CH_IN);
        let _ = dma.wait_complete(CH_IN, 4_000_000);
        let _ = dma.wait_complete(CH_OUT, 4_000_000);
        dma.clear_flags(CH_IN);
        dma.clear_flags(CH_OUT);
        self.cryp.disable_dma();

        // Pull the DMA-written ciphertext into the CPU's view.
        hpdma::dcache_invalidate_range(data.as_mut_ptr() as usize, byte_count as usize);
    }
}
