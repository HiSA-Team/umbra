/* Standalone Umbra enclave blob linker script.
 *
 * Output: a flat binary (after `objcopy -O binary`) containing the
 * 48-byte enclave header at offset 0 followed by the enclave code +
 * data, ready to flash at any 4 KB-aligned NS-flash slot scanned by
 * the bare_metal (L5) host (see host/stm32l552/bare_metal/src/main.c).
 *
 * ORIGIN=0x0 is intentional: PIC code (compiled with -fpic) uses
 * PC-relative loads throughout, so the absolute link address doesn't
 * matter — only the relative layout within the blob does, which is
 * preserved when the kernel copies it from flash to ESS at runtime.
 */

/* enclave_entry is the live root; ld --gc-sections traces from here and
 * drops unreachable upstream functions (e.g. prime_init/main/return when
 * the wrapper only calls prime_prime). Without an ENTRY directive, gc
 * defaults to `_start` which we don't define → everything would be eligible
 * for collection including enclave_entry itself.
 */
ENTRY(enclave_entry)

MEMORY {
    /* 32 KB window sized to fit the paper apps (ndes ~7 KB protected,
     * statemate ~13 KB protected). The ._enclave_code reservation below
     * stays at 0x4000 (16 KB plaintext); the extra room in FLASH_BLOB is
     * headroom for objcopy's section extraction.
     *
     * Caveat: bare_metal (L5) scans on 4 KB boundaries, so any enclave
     * whose protected .bin exceeds 4 KB will overlap with the next scan
     * slot. The multi-enclave all-at-once test mode in test_taclebench.sh
     * can only fit enclaves whose protected .bin is < 4 KB. Sequential
     * mode (one bench at a time, NS-flash erased between passes) works
     * for any blob size up to the FLASH_BLOB reservation. */
    FLASH_BLOB (RX) : ORIGIN = 0x0, LENGTH = 32K
}

SECTIONS {
    ._enclave_header 0x0 : {
        KEEP(*(.app.enclave_header))
    } > FLASH_BLOB

    ._enclave_code : ALIGN(4) {
        _enclave_code_start = .;

        /* enclave_entry — must be first byte in the code region; KEEP
         * keeps it alive across --gc-sections. */
        KEEP(*(.app.enclave_code))

        /* Upstream TACLeBench functions + globals. NO KEEP() here so
         * --gc-sections drops anything enclave_entry doesn't reach.
         * .text.main is /DISCARD/-ed below as a final safety net.
         *
         * Wildcards use the `*(.foo*)` form (no dot before the *), which
         * matches BOTH `.foo` (plain, e.g. literal array initialisers
         * GCC emits regardless of -fdata-sections) AND `.foo.suffix`
         * (per-function/per-data sections from -ffunction-sections /
         * -fdata-sections). The earlier `*(.rodata.*)` form (with a dot)
         * missed plain `.rodata`, leaving it as an orphan section that
         * the linker placed BETWEEN ._enclave_header and ._enclave_code.
         * `objcopy --only-section` then filled the gap with zeros,
         * shifting the actual code+sig+meta bytes past where the kernel
         * expected them at flash offset 48 → chained-measurement FAIL. */
        *(.text*)
        *(.bss*)
        *(.data*)
        *(.rodata*)

        /* GCC emits .got / .got.plt for PIC code that references global
         * symbols (heavy paper-apps: anagram, statemate, dijkstra,
         * huff_dec, cjpeg_wrbmp). Without explicit absorption here, ld
         * places them as ORPHAN sections AFTER ._enclave_code's padding
         * (i.e. at `_enclave_code_start + 0x5000` thanks to the trailing
         * `. = _enclave_code_start + 0x5000` below). `objcopy
         * --only-section=._enclave_code` then extracts JUST ._enclave_code,
         * leaving the GOT entries off the blob. At runtime the enclave's
         * `add rN, pc, #imm` PIC fixups compute target addresses inside
         * the (absent) GOT — those land past the last allocated EFBC slot
         * and trap with MemManage "addr outside any enclave" (R0=0x0,
         * MMFAR≈ess_base+0x5000+). Pulling them inside ._enclave_code
         * makes the offsets resolve to bytes that ARE in the blob.
         *
         * KEEP() is required because the symbols inside .got might not
         * have explicit references that survive --gc-sections. */
        KEEP(*(.got))
        KEEP(*(.got.plt))

        /* Marker for the end of actual content (code + data + bss),
         * BEFORE the reservation padding below. `protect_enclave.py`
         * reads this symbol via `nm` to size the protected blob so it
         * covers globals, not just code — otherwise enclaves that touch
         * .data/.bss globals get an under-sized ESS allocation and the
         * first global access past the code-only region traps the
         * MemManage handler with "addr outside any enclave". */
        . = ALIGN(4);
        _enclave_code_end = .;

        /* Reserve enough space for protect_enclave.py's output. Each
         * ess_miss_recovery-style protected block is 32B HMAC + 32B meta +
         * 256B ciphertext = 320 bytes. The linker-recorded section size
         * MUST be ≥ that output, otherwise objcopy truncates the
         * ciphertext on extraction (silently corrupting the blob).
         *
         * 0x5000 gives headroom for ~64
         * protected blocks (~16 KB plaintext). Sized to fit the paper-
         * extension app set ):
         *   ndes:         15 blocks → 4800 B protected   (4 KB plaintext)
         *   statemate:    ~41 blocks → ~13 KB protected  (~10 KB plaintext)
         *   anagram-200:  ~50 blocks → ~16 KB protected  (~12 KB plaintext)
         *   cjpeg_wrbmp:  ~38 blocks → ~11 KB protected  (~10 KB plaintext)
         *   dijkstra-64:  ~64 blocks → ~20 KB protected  (~16 KB plaintext)
         *
         * Upstream dijkstra (100X100, QUEUE=1000) is NOT VIABLE — 28 KB
         * plaintext exceeds the 28 KB NS-flash slot. The reduced 64X64
         * variant in blob_src/dijkstra_input_small.c stays within budget.
         *
         * If you hit "cannot move location counter backwards" here, the
         * benchmark plaintext is too large — bump this AND FLASH_BLOB
         * above. Caveat: enclave .bin > 4 KB overlaps the next host
         * scan slot (bare_metal (L5) scans on PAGE_SIZE=0x1000 boundaries),
         * so the multi-enclave all-at-once test mode can only fit
         * enclaves whose protected .bin is < 4 KB. Sequential mode
         * (one bench at a time, NS-flash erased between passes) works
         * for any blob size up to the FLASH_BLOB reservation.
         */
        . = _enclave_code_start + 0x5000;
    } > FLASH_BLOB

    /DISCARD/ : {
        *(.text.main)        /* upstream's unused main() */
        *(.note.*)
        *(.comment)
        *(.eh_frame*)
        *(.ARM.*)
        *(.debug_*)
    }
}
