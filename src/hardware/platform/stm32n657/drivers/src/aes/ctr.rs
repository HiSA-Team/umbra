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

    /// Native HW CTR override.
    /// Reconfigures CRYP from ECB (left over from `init`) to CTR mode with
    /// `iv` as the initial counter, then streams `data` through the same
    /// FIFO protocol used by `process_block`. CRYP handles counter
    /// increment and XOR internally — the output of `process_block` is
    /// already the ciphertext/plaintext, not raw keystream.
    /// Trade-off vs default impl: saves one ECB encrypt+XOR loop per block
    /// in software, but adds a one-time CRYP reconfiguration cost. Worth
    /// it for any payload ≥ 2 blocks. For 1 block the difference is
    /// negligible.
    fn ctr_xform(&mut self, iv: &[u8; 16], data: &mut [u8]) {
        let chunks = data.len() / 16;
        if chunks == 0 {
            return;
        }

        // Reconfigure CRYP to CTR mode with the SAES-shared key (no KEYRx
        // writes). If V4 finds the shared key does not survive the ECB→CTR
        // switch, the orchestrator re-shares before the decrypt; see
        // configure_ctr_shared docs.
        self.cryp.configure_ctr_shared(iv);

        let mut block = [0u8; 16];
        let mut out_block = [0u8; 16];
        let mut i: usize = 0;
        while i < chunks {
            // Stage one 16-byte ciphertext block in scratch
            let mut j: usize = 0;
            while j < 16 {
                block[j] = data[i * 16 + j];
                j += 1;
            }

            // CRYP in CTR mode XORs internally — `out_block` is the
            // post-XOR result, not raw keystream.
            self.cryp.process_block(&block, &mut out_block);

            let mut j: usize = 0;
            while j < 16 {
                data[i * 16 + j] = out_block[j];
                j += 1;
            }
            i += 1;
        }
    }
}
