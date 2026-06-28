//! Paravirtualization helpers for the M-mode gateway: decode a trapped S-mode
//! Zicsr instruction, classify PMP-range CSRs, apply the CSR read/modify/write
//! semantics, and decode/clamp a guest NAPOT PMP entry into a physical region.
//! All pure and host-tested; the monitor side (shadow table, CSR I/O, sPMP
//! programming) lives in `secure_kernel/paravirt.rs`.

/// The six Zicsr instruction kinds (funct3 001/010/011/101/110/111).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CsrKind {
    Rw,  // csrrw
    Rs,  // csrrs
    Rc,  // csrrc
    Rwi, // csrrwi
    Rsi, // csrrsi
    Rci, // csrrci
}

/// A decoded Zicsr instruction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CsrOp {
    pub csr: u16,
    pub rd: u8,
    /// Source register index (Rw/Rs/Rc) or 5-bit zero-extended immediate (i-forms).
    pub rs1_uimm: u8,
    pub kind: CsrKind,
}

/// PMP cfg CSRs (RV32: pmpcfg0..3) and addr CSRs (pmpaddr0..15).
const PMPCFG_LO: u16 = 0x3A0;
const PMPCFG_HI: u16 = 0x3A3;
const PMPADDR_LO: u16 = 0x3B0;
const PMPADDR_HI: u16 = 0x3BF;

/// Decode a 32-bit instruction word into a [`CsrOp`], or `None` if it is not a
/// SYSTEM/Zicsr instruction (so a genuine illegal instruction falls through to
/// the fault handler). Zicsr is 32-bit only — no compressed form.
pub fn decode_csr(word: u32) -> Option<CsrOp> {
    if word & 0x7f != 0x73 {
        return None; // not SYSTEM opcode
    }
    let funct3 = (word >> 12) & 0x7;
    let kind = match funct3 {
        0b001 => CsrKind::Rw,
        0b010 => CsrKind::Rs,
        0b011 => CsrKind::Rc,
        0b101 => CsrKind::Rwi,
        0b110 => CsrKind::Rsi,
        0b111 => CsrKind::Rci,
        _ => return None, // funct3 000 = ecall/ebreak/mret/etc, not a CSR op
    };
    Some(CsrOp {
        csr: (word >> 20) as u16 & 0xfff,
        rd: ((word >> 7) & 0x1f) as u8,
        rs1_uimm: ((word >> 15) & 0x1f) as u8,
        kind,
    })
}

/// True for the PMP configuration/address CSRs this gateway emulates.
pub fn is_pmp_csr(csr: u16) -> bool {
    (PMPCFG_LO..=PMPCFG_HI).contains(&csr) || (PMPADDR_LO..=PMPADDR_HI).contains(&csr)
}

/// Index into a flat 16-entry shadow: pmpcfg byte register, or pmpaddr index.
/// Returns `(is_cfg, index)` — for pmpcfg the index is the cfg *register* (0..3),
/// for pmpaddr the index is the entry (0..15).
pub fn pmp_csr_index(csr: u16) -> Option<(bool, usize)> {
    if (PMPCFG_LO..=PMPCFG_HI).contains(&csr) {
        Some((true, (csr - PMPCFG_LO) as usize))
    } else if (PMPADDR_LO..=PMPADDR_HI).contains(&csr) {
        Some((false, (csr - PMPADDR_LO) as usize))
    } else {
        None
    }
}

/// Apply the read/modify/write semantics of `kind` to produce the new CSR value.
/// `old` is the current (shadow) value; `operand` is the source register value
/// (Rw/Rs/Rc) or the zero-extended immediate (i-forms).
pub fn apply_csr(kind: CsrKind, old: u32, operand: u32) -> u32 {
    match kind {
        CsrKind::Rw | CsrKind::Rwi => operand,
        CsrKind::Rs | CsrKind::Rsi => old | operand,
        CsrKind::Rc | CsrKind::Rci => old & !operand,
    }
}

/// Decode a guest NAPOT PMP entry (`cfg` byte + `pmpaddr` word) into
/// `(base, end, r, w, x)`, or `None` if the entry is OFF or not NAPOT. The `A`
/// field is bits 4:3 (3 = NAPOT); R/W/X are bits 0/1/2. NAPOT: the address word
/// has the region encoded as a run of low 1-bits; `base = (addr & !mask) << 2`,
/// `size = (mask+1) << 3`.
pub fn decode_pmp_napot(cfg: u8, addr: u32) -> Option<(u32, u32, bool, bool, bool)> {
    let a = (cfg >> 3) & 0b11;
    if a != 0b11 {
        return None; // OFF / TOR / NA4 not handled in this slice
    }
    // NAPOT: `m` trailing 1-bits in the (word-shifted) address encode the size;
    // size = 1 << (m + 3) bytes, base = (addr with those bits cleared) << 2.
    let m = addr.trailing_ones();
    if m >= 29 {
        return None; // size would overflow a 32-bit region (whole-memory rule)
    }
    let size: u64 = 1u64 << (m + 3);
    let low = (1u32 << m).wrapping_sub(1);
    let base = (addr & !low) << 2;
    Some((
        base,
        (base as u64 + size) as u32,
        cfg & 0b001 != 0,
        cfg & 0b010 != 0,
        cfg & 0b100 != 0,
    ))
}

/// Clamp `[base, end)` to the guest's world `[wbase, wend)`. Returns `None` if
/// the requested region is not *fully* inside the world — the gateway then denies
/// the entry rather than granting a partial region (sPMP can only restrict).
pub fn clamp_to_world(base: u32, end: u32, wbase: u32, wend: u32) -> Option<(u32, u32)> {
    if base >= wbase && end <= wend && base < end {
        Some((base, end))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_csrrw_to_pmpcfg0() {
        // csrrw x0, pmpcfg0, x5  → csr=0x3A0, funct3=001, rs1=5, rd=0, op=0x73
        let word = (0x3A0u32 << 20) | (5 << 15) | (0b001 << 12) | (0 << 7) | 0x73;
        let op = decode_csr(word).unwrap();
        assert_eq!(op.csr, 0x3A0);
        assert_eq!(op.rs1_uimm, 5);
        assert_eq!(op.kind, CsrKind::Rw);
        assert!(is_pmp_csr(op.csr));
        assert_eq!(pmp_csr_index(op.csr), Some((true, 0)));
    }

    #[test]
    fn decodes_pmpaddr3() {
        let word = (0x3B3u32 << 20) | (6 << 15) | (0b001 << 12) | 0x73;
        let op = decode_csr(word).unwrap();
        assert_eq!(pmp_csr_index(op.csr), Some((false, 3)));
    }

    #[test]
    fn rejects_non_system_opcode() {
        assert_eq!(decode_csr(0x0000_0000), None); // illegal / trap-fill
        assert_eq!(decode_csr(0x0000_0013), None); // addi (opcode 0x13)
    }

    #[test]
    fn rejects_funct3_zero_priv_op() {
        // ecall = 0x00000073 (funct3=000) is SYSTEM but not a CSR op.
        assert_eq!(decode_csr(0x0000_0073), None);
    }

    #[test]
    fn non_pmp_csr_is_not_emulated() {
        assert!(!is_pmp_csr(0x300)); // mstatus
        assert!(!is_pmp_csr(0x3F0)); // beyond pmpaddr15
    }

    #[test]
    fn apply_csr_semantics() {
        assert_eq!(apply_csr(CsrKind::Rw, 0xFFFF, 0x000F), 0x000F);
        assert_eq!(apply_csr(CsrKind::Rs, 0x00F0, 0x000F), 0x00FF);
        assert_eq!(apply_csr(CsrKind::Rc, 0x00FF, 0x000F), 0x00F0);
    }

    #[test]
    fn decodes_napot_region() {
        // 64 KB NAPOT at 0x8011_0000: size=0x10000 -> (size>>3 -1)=0x1FFF run.
        // pmpaddr = (base>>2) | ((size>>3)-1) = 0x2004_4000 | 0x1FFF = 0x2004_5FFF
        let addr = (0x8011_0000u32 >> 2) | 0x1FFF;
        let cfg = 0b001 | (0b11 << 3); // R + NAPOT
        let (base, end, r, w, x) = decode_pmp_napot(cfg, addr).unwrap();
        assert_eq!(base, 0x8011_0000);
        assert_eq!(end, 0x8012_0000);
        assert!(r && !w && !x);
    }

    #[test]
    fn off_or_tor_entry_is_none() {
        assert_eq!(decode_pmp_napot(0b001, 0x2004_5FFF), None); // A=OFF
        assert_eq!(decode_pmp_napot(0b001 | (0b01 << 3), 0), None); // A=TOR
    }

    #[test]
    fn clamp_inside_world_is_identity() {
        assert_eq!(
            clamp_to_world(0x8011_0000, 0x8012_0000, 0x8010_0000, 0x8020_0000),
            Some((0x8011_0000, 0x8012_0000))
        );
    }

    #[test]
    fn clamp_outside_world_is_denied() {
        // Tries to reach the ESS region (above the host world) -> denied.
        assert_eq!(
            clamp_to_world(0x8011_0000, 0x8020_8000, 0x8010_0000, 0x8020_0000),
            None
        );
    }
}
