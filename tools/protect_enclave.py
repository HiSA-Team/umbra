import sys
import os
import subprocess
import re
import struct
import hmac
import hashlib
import binascii
import tempfile

# --- Configuration ---
# Size of the executable code block (in bytes) that is loaded into RAM.
#: build-time knob via UMBRA_SLOT_SIZE_BYTES env var
# (default supplied by .cargo/config.toml [env]). Must match the kernel
# build for the same target — the sweep harness runs ./rebuild_all.sh
# under the same env so both sides observe the same value.
CODE_BLOCK_SIZE = int(os.environ.get("UMBRA_SLOT_SIZE_BYTES", "256"))
# Size of the metadata header per block (excluding the data itself)
# We will define this dynamically or fixed.

# Cross-toolchain prefix for objdump/objcopy/nm/readelf. Defaults to the ARM
# bare-metal triple (STM32 platforms). RISC-V overrides it via
# UMBRA_CROSS=riscv64-unknown-elf- so the SAME tool serves every target.
CROSS = os.environ.get("UMBRA_CROSS", "arm-none-eabi-")

# Target architecture, derived from the toolchain prefix. The block split,
# encryption, metadata, and chained measurement are arch-independent; only the
# disassembly-driven reachability (Stage 5) and the static-PIE relocation family
# differ between ARM Thumb and RISC-V.
IS_RISCV = "riscv" in CROSS


def assert_demand_paging_safe(demand_paging, reloc_count):
    """Refuse demand-paging on a blob with cross-block data references.

    Demand-paging evicts non-entry blocks; a data load to an evicted block
    would silently read 0xDEDEDEDE (no HW data-read trap on L552) and walk a
    wild pointer. reloc_count > 0 means such cross-block data refs exist, so we
    fail the build instead. Only code-only blobs (reloc_count == 0) are allowed.
    """
    if demand_paging and reloc_count > 0:
        sys.exit(
            f"Error: UMBRA_DEMAND_PAGING set but blob has {reloc_count} "
            f"cross-block data references (reloc_count > 0); not safe for "
            f"demand-paging mode (only code-only benches with reloc_count == 0)."
        )


# RISC-V control-flow mnemonics with a STATIC target (the reachability edge).
# jalr/jr/ret/c.jr/c.jalr are indirect (no statically-known target) → excluded.
# jal/c.jal are calls (they return → the block also falls through).
RISCV_BRANCH_MNEMONICS = {
    "jal", "j", "c.j", "c.jal",
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "beqz", "bnez", "blez", "bgez", "bltz", "bgtz",
    "bgt", "ble", "bgtu", "bleu",
    "c.beqz", "c.bnez",
}
# RISC-V instructions that END a block's control flow (no fall-through to the
# next block). Unconditional jumps + returns; `jal`/`c.jal` (calls) DO fall
# through, conditional branches DO fall through.
RISCV_UNCOND_MNEMONICS = {"j", "c.j", "jr", "c.jr", "ret", "tail", "mret"}


def _is_branch(mnem):
    """Does `mnem` carry a static intra-enclave control-flow edge?"""
    if IS_RISCV:
        return mnem in RISCV_BRANCH_MNEMONICS
    # ARM Thumb: b/bl/bx/beq/... and the c* conditionals.
    return mnem.startswith("b") or mnem.startswith("c") or "bl" in mnem

def run_cmd(args):
    """Run a subprocess command and return output."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        return result.stdout
    except FileNotFoundError:
        print(f"Error: required tool not found on PATH: {args[0]}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {' '.join(args)}\n{e.stderr}")
        sys.exit(1)

def get_section_info(elf_path, section_name):
    """Get section offset, size, and address using objdump."""
    output = run_cmd([f"{CROSS}objdump", "-h", elf_path])
    # Idx Name Size VMA LMA File off Algn
    #  1 .app.enclave_code 00000400 ...
    for line in output.splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[1] == section_name:
            # size is parts[2], vma is parts[3], file_off is parts[5]
            return {
                "size": int(parts[2], 16),
                "vma": int(parts[3], 16),
                "offset": int(parts[5], 16)
            }
    return None

def extract_section(elf_path, section_name, output_file):
    """Extract section content to a file."""
    run_cmd([
        f"{CROSS}objcopy",
        "-O", "binary",
        f"--only-section={section_name}",
        elf_path,
        output_file
    ])

def update_section(elf_path, section_name, input_file):
    """Update section content from a file."""
    run_cmd([
        f"{CROSS}objcopy",
        "--update-section", f"{section_name}={input_file}",
        elf_path
    ])

def extract_static_pie_reloc_vmas(elf_path, section_name, section_vma, section_bytes):
    """Return a sorted set of elements within `section_name` that hold absolute
    addresses needing runtime relocation. Two sources:

    (1) R_ARM_ABS32 — pointer-array initialisers like
        `char const *dict[2279] = {"a","b",...}`. The reloc OFFSET itself
        is the slot VMA: the linker has resolved the absolute address
        in-place, and we just need its location.

    (2) R_ARM_GOT_BREL — GOT-relative loads in code reference GOT slots
        that the linker (static-PIE) has filled with absolute addresses.
        The reloc OFFSET is the CODE site, not the GOT slot, so we read
        the 4-byte literal there (= section-relative offset of the GOT
        entry from section start) and translate to a VMA.

    Without (2), heavy paper-apps with GOT-routed `extern` references
    (anagram → `anagram_dictionary`, dijkstra → adjacency tables, …)
    MemManage with R3 holding the slot's compile-time address (e.g.
    `0x2270`) the moment the enclave first dereferences a pointer the
    linker baked into the GOT.

    Requires the ELF to be linked with `--emit-relocs` so the `.rel.*`
    sections survive the static link.

    NOTE: We DELIBERATELY ignore R_ARM_REL32 / R_ARM_THM_CALL /
    R_ARM_BASE_PREL — those are PC-relative encodings and resolve
    correctly at runtime without any fixup.
    """
    output = run_cmd([f"{CROSS}readelf", "-W", "-r", elf_path])
    rel_section_header = f".rel{section_name}"
    in_target = False
    vmas = set()
    for line in output.splitlines():
        if line.startswith("Relocation section"):
            in_target = rel_section_header in line
            continue
        if not in_target:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        # Lines look like:
        #   "00002264  00000202 R_ARM_ABS32       00000030  ._enclave_code"
        #   "00000214  0000591a R_ARM_GOT_BREL    00002270  anagram_dictionary"
        try:
            reloc_offset = int(parts[0], 16)
        except ValueError:
            continue
        rtype = parts[2]
        if rtype == "R_ARM_ABS32":
            vmas.add(reloc_offset)
        elif rtype == "R_ARM_GOT_BREL":
            # The 4-byte literal at the code site is the section-relative
            # offset of the symbol's GOT slot. Translate to a VMA.
            sec_off = reloc_offset - section_vma
            if 0 <= sec_off and sec_off + 4 <= len(section_bytes):
                lit = struct.unpack(
                    "<I", section_bytes[sec_off : sec_off + 4]
                )[0]
                got_slot_vma = section_vma + lit
                vmas.add(got_slot_vma)
    return sorted(vmas)


def parse_disassembly(elf_path, section_name):
    """
    Parse disassembly to find branch targets and literal loads.
    Returns:
        instructions: list of (addr, size, mnemonic, op_str, bytes)
        labels: dict of addr -> name
    """
    cmd = [f"{CROSS}objdump", "-d", f"--section={section_name}", elf_path]
    output = run_cmd(cmd)
    
    instructions = []
    labels = {}
    
    # Regex for lines: " 8000100:	4b01      	ldr	r3, [pc, #4]	; (8000108 <main+0x8>)"
    # Or " 8000100: <symbol>:"
    line_re = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f ]+)\s+([a-z0-9\.]+)(\s+.*)?$")
    label_re = re.compile(r"^\s*([0-9a-f]+)\s+<([^>]+)>:$")
    
    for line in output.splitlines():
        # Check label
        m_label = label_re.match(line)
        if m_label:
            addr = int(m_label.group(1), 16)
            name = m_label.group(2)
            labels[addr] = name
            continue
            
        m_instr = line_re.match(line)
        if m_instr:
            addr = int(m_instr.group(1), 16)
            hex_bytes = m_instr.group(2).strip()
            mnemonic = m_instr.group(3)
            op_str = m_instr.group(4).strip() if m_instr.group(4) else ""
            
            # remove comments from op_str (starting with ;)
            if ';' in op_str:
                op_str = op_str.split(';')[0].strip()
                
            hex_clean = hex_bytes.replace(" ", "")
            # Tolerate odd-length hex from objdump on PIC blobs where .data/.bss
            # bytes are interleaved with code in `._enclave_code` and don't
            # form complete Thumb instructions. The downstream
            # sequential-fallthrough pass still threads reachability for data
            # regions; skipping malformed lines silently is safe.
            if len(hex_clean) % 2 != 0:
                continue
            size = len(hex_clean) // 2
            instructions.append({
                "addr": addr,
                "size": size,
                "mnemonic": mnemonic,
                "op_str": op_str,
                "bytes": binascii.unhexlify(hex_clean)
            })
            
    return instructions, labels

def encrypt_block(data, key):
    """Encrypt data using AES-128-CTR via OpenSSL (matching debug_hmac.py)."""
    key_hex = key.hex()
    iv_hex = "00" * 16  # Fixed IV for now (should be random in production but matching earlier context)

    with tempfile.TemporaryDirectory(prefix="umbra_enc_") as tmpdir:
        pt_path = os.path.join(tmpdir, "pt.bin")
        ct_path = os.path.join(tmpdir, "ct.bin")
        with open(pt_path, "wb") as f:
            f.write(data)

        run_cmd([
            "openssl", "enc", "-aes-128-ctr", "-in", pt_path, "-out", ct_path,
            "-K", key_hex, "-iv", iv_hex, "-nosalt"
        ])

        with open(ct_path, "rb") as f:
            return f.read()

def load_symbols(elf_path):
    """Load symbols from ELF using nm, including local symbols."""
    # -a: debug-syms, -n: numeric sort
    output = run_cmd([f"{CROSS}nm", "-a", "-n", elf_path])

    syms = {}
    for line in output.splitlines():
        # Format: 0800xxxx t .L3
        parts = line.split()
        if len(parts) >= 3:
            try:
                addr = int(parts[0], 16)
                name = parts[-1]
                syms[name] = addr
            except ValueError:
                pass
    return syms

def flat_protect(elf_file, key_file):
    """Single-block "flat" EFB for the RISC-V monitor (set UMBRA_CROSS=riscv64-
    unknown-elf-). Encrypt the whole `._enclave_code` with AES-128-CTR, measure
    the CIPHERTEXT (encrypt-then-MAC), patch the 48-byte `._enclave_header`
    (code_size@10, hmac@16), and write the ciphertext back into the ELF.

    No block container / reachability / relocations: the riscv enclave is a
    single PC-relative block. The monitor (`secure_kernel::create`) verifies
    HMAC(MASTER_KEY, ciphertext), then AES-128-CTR-decrypts in the Secure ESS
    before executing — the same encrypt-then-MAC ordering as the ARM EFB path,
    reusing this tool's `encrypt_block` + ENC_KEY_LABEL KDF.
    """
    with open(key_file, "rb") as f:
        master_key = f.read(32)
    enc_key = hmac.new(master_key, b"umbra-enc-v1", hashlib.sha256).digest()[:16]

    if not get_section_info(elf_file, "._enclave_code"):
        print("Error: ._enclave_code section not found")
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="umbra_flat_") as d:
        pt = os.path.join(d, "pt.bin")
        extract_section(elf_file, "._enclave_code", pt)
        with open(pt, "rb") as f:
            plain = f.read()

        cipher = encrypt_block(plain, enc_key)  # AES-128-CTR over the whole code
        if len(cipher) != len(plain):
            print(f"Error: ciphertext length {len(cipher)} != plaintext {len(plain)}")
            sys.exit(1)
        mac = hmac.new(master_key, cipher, hashlib.sha256).digest()

        ct = os.path.join(d, "ct.bin")
        with open(ct, "wb") as f:
            f.write(cipher)
        update_section(elf_file, "._enclave_code", ct)

        hdr = os.path.join(d, "hdr.bin")
        extract_section(elf_file, "._enclave_header", hdr)
        with open(hdr, "rb") as f:
            hb = bytearray(f.read())
        if len(hb) < 48:
            print(f"Error: header too small ({len(hb)} bytes)")
            sys.exit(1)
        struct.pack_into("<I", hb, 10, len(cipher))  # code_size
        hb[16:48] = mac                               # hmac
        with open(hdr, "wb") as f:
            f.write(hb)
        update_section(elf_file, "._enclave_header", hdr)

    print(f"[Protect] flat: enc_key={enc_key.hex()} measurement={mac.hex()} "
          f"over {len(cipher)} ciphertext bytes")


ENCVER_LABEL = b"umbra-encver-v1"


def version_tag(bm: bytes, author_id: int, version: int) -> bytes:
    """Bind (author_id, version) to the block measurement BM by a trailing HMAC.
    MUST match the kernel's version-derivation. The result replaces the stamped
    measurement ONLY when UMBRA_VERSION_BIND=1; the version is never written in
    clear, so it cannot be tampered without breaking this tag."""
    return hmac.new(
        bm, ENCVER_LABEL + struct.pack("<II", author_id, version), hashlib.sha256
    ).digest()


def main():
    # Strip optional flags out of argv so the positional parsing below is
    # unchanged. Flags: --hmac-over-plaintext (L562 path), --flat (RISC-V
    # single-block path).
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    hmac_over_plaintext = "--hmac-over-plaintext" in sys.argv[1:]
    flat_mode = "--flat" in sys.argv[1:]

    # RISC-V single-block path: `protect_enclave.py --flat <elf_file> <key_file>`.
    if flat_mode:
        if len(argv) < 2:
            print("Usage: protect_enclave.py --flat <elf_file> <key_file>")
            sys.exit(1)
        flat_protect(argv[0], argv[1])
        return

    if len(argv) < 3:
        print("Usage: protect_enclave.py [--hmac-over-plaintext] <elf_file> <main_c> <key_file> [obj_dir]")
        sys.exit(1)

    elf_file = argv[0]
    # argv[1] = main_c — positional placeholder, currently unused
    key_file = argv[2]
    
    print(f"[Protect] Processing {elf_file}...")
    
    # Load Symbols (compiler CFG info)
    symbol_map = load_symbols(elf_file)
    print(f"[Protect] Loaded {len(symbol_map)} symbols")

    # 1. Load Key
    with open(key_file, "rb") as f:
        master_key = f.read(32) # 32 bytes
    # Derive enc_key and hmac_key from master_key via HMAC-based KDF.
    # Must stay in sync with key_derivation.rs labels.
    ENC_KEY_LABEL = b"umbra-enc-v1"
    aes_key = hmac.new(master_key, ENC_KEY_LABEL, hashlib.sha256).digest()[:16]
    hmac_key = master_key
    
    # 2. Get Section Info
    sec_info = get_section_info(elf_file, "._enclave_code")
    if not sec_info:
        print("Error: ._enclave_code section not found")
        sys.exit(1)
        
    print(f"[Protect] Section ._enclave_code: VMA=0x{sec_info['vma']:x}, Size={sec_info['size']}")
    
    # 3. Extract Raw Code
    with tempfile.TemporaryDirectory(prefix="umbra_protect_") as tmpdir:
        raw_code_file = os.path.join(tmpdir, "raw_code.bin")
        extract_section(elf_file, "._enclave_code", raw_code_file)
        with open(raw_code_file, "rb") as f:
            full_code = f.read()
    
    insts, labels = parse_disassembly(elf_file, "._enclave_code")
    
    if not insts:
        print("Error: No instructions found in section")
        sys.exit(1)
        
    # Determine code constraints.
    #
    # Prefer the linker-emitted _enclave_code_end symbol so the size covers
    # .text + .rodata + .data + .bss (everything that gets loaded into the
    # ESS region under -fpic -mpic-data-is-text-relative). The fallback
    # (end-of-last-instruction) is the historical behaviour and is kept for
    # blobs built against older linker scripts; it misses .data/.bss and
    # under-sizes the kernel ESS allocation, causing global writes past the
    # code-only region to trap MemManage with "addr outside any enclave".
    start_addr = sec_info['vma']
    end_sym   = symbol_map.get("_enclave_code_end")
    start_sym = symbol_map.get("_enclave_code_start")
    if end_sym is not None and start_sym is not None:
        code_len = end_sym - start_sym
        print(f"[Protect] Detected Code+Data Length: {code_len} bytes "
              f"(from _enclave_code_end)")
    else:
        code_len = (insts[-1]['addr'] + insts[-1]['size']) - start_addr
        print(f"[Protect] Detected Code Length: {code_len} bytes "
              f"(no _enclave_code_end symbol; .data/.bss may be missed)")

    # `end_addr` is the upper bound of the enclave's content in VMA space.
    # Downstream code (Stage 5: branch-target → block-idx classification)
    # uses it to decide whether a `bl`/`b` target lives inside this enclave.
    end_addr = start_addr + code_len

    # Trim/pad full_code to code_len. The extracted ._enclave_code section
    # contains any in-section .bss bytes materialised as zeros (the linker
    # promotes mixed-content output sections to PROGBITS); if the section
    # was shorter than code_len for some reason we pad with zeros so the
    # block splitter below still produces a self-consistent blob.
    if len(full_code) > code_len:
        full_code = full_code[:code_len]
    elif len(full_code) < code_len:
        full_code = full_code + b"\x00" * (code_len - len(full_code))
    
    # 4. Split into EFBs
    blocks = []
    num_blocks = (len(full_code) + CODE_BLOCK_SIZE - 1) // CODE_BLOCK_SIZE
    print(f"[Protect] Splitting into {num_blocks} blocks of size {CODE_BLOCK_SIZE}")
    
    for i in range(num_blocks):
        offset = i * CODE_BLOCK_SIZE
        chunk = full_code[offset : offset + CODE_BLOCK_SIZE]
        if len(chunk) < CODE_BLOCK_SIZE:
             chunk += b'\x00' * (CODE_BLOCK_SIZE - len(chunk))
             
        blocks.append({
            "id": i,
            "data": chunk,
            "vma_start": start_addr + offset,
            "vma_end": start_addr + offset + CODE_BLOCK_SIZE,
            "reachable": set()
        })

    # 5. Analyze Branches

    # Cross-block PC-relative data accesses (literal pools, `adr`, `add rN, pc,
    # #imm`) break the eviction model: blocks are self-contained code units,
    # but a literal-pool load from block N into block M's address raises a
    # data-access fault that `umbra_mem_manage_handler` / `umbra_bus_fault_handler`
    # do not recover (they only rescue instruction-fetch IBUSERR/IACCVIOL).
    #
    # Collect every offending site and fail the build at the end so the whole
    # set is visible in one shot.
    pc_rel_violations = []

    def _check_pc_rel(ins, addr, blk_idx):
        op_str = ins['op_str']
        mnem = ins['mnemonic']
        target_addr = None

        # `ldr rN, [pc, #imm]` — literal pool load.
        if mnem.startswith('ldr') and 'pc' in op_str:
            m = re.search(r'\[pc,\s*#?(-?(?:0x)?[0-9a-f]+)\]', op_str)
            if m:
                try:
                    offset_val = int(m.group(1), 0)
                    # PC reads as (current + 4) on Thumb, word-aligned for ldr.
                    target_addr = ((addr + 4) + offset_val) & ~3
                except ValueError:
                    return

        # `adr rN, <label>` — PC-relative address materialization.
        elif mnem.startswith('adr'):
            m = re.search(r'0x([0-9a-f]+)', op_str)
            if m:
                try:
                    target_addr = int(m.group(1), 16)
                except ValueError:
                    return

        # `add rN, pc, #imm` — another way to materialize a PC-relative address.
        elif mnem.startswith('add') and re.search(r'\bpc\b', op_str):
            m = re.search(r'#(-?(?:0x)?[0-9a-f]+)', op_str)
            if m:
                try:
                    offset_val = int(m.group(1), 0)
                    target_addr = ((addr + 4) + offset_val) & ~3
                except ValueError:
                    return

        if target_addr is None:
            return
        target_blk_idx = (target_addr - start_addr) // CODE_BLOCK_SIZE
        if target_blk_idx != blk_idx and 0 <= target_blk_idx < num_blocks:
            pc_rel_violations.append({
                'addr': addr,
                'mnemonic': mnem,
                'op_str': op_str,
                'target': target_addr,
                'src_blk': blk_idx,
                'dst_blk': target_blk_idx,
            })

    for ins in insts:
        addr = ins['addr']
        blk_idx = (addr - start_addr) // CODE_BLOCK_SIZE
        if blk_idx < 0 or blk_idx >= num_blocks:
            continue

        block = blocks[blk_idx]

        # PC-relative cross-block DATA access check is ARM-specific (ldr [pc],
        # adr, add pc). RISC-V materializes addresses via auipc+offset; that
        # detection is deferred, so skip the ARM probe on RISC-V (it never
        # matches RISC-V mnemonics anyway).
        if not IS_RISCV:
            _check_pc_rel(ins, addr, blk_idx)

        # Check for BRANCHES (static intra-enclave control-flow edges).
        if _is_branch(ins['mnemonic']):
            target_val = None
            
            # Strategy 1: Check for Symbol Label in Disassembly (Compiler CFG)
            # objdump output: "bl 8000x <.L3>"
            m_sym = re.search(r'<([^>]+)>', ins['op_str'])
            if m_sym:
                sym_name = m_sym.group(1)
                # Ignore offsets like "frame_dummy+0x24" if simpler alias exists?
                # Sometimes sym_name is ".L3+0x4".
                base_sym = sym_name.split('+')[0] 
                
                if sym_name in symbol_map:
                    target_val = symbol_map[sym_name]
                elif base_sym in symbol_map:
                    # Approximation
                    target_val = symbol_map[base_sym]
            
            # Strategy 2: Hex Address
            if target_val is None:
                args = re.split(r'[,\s]+', ins['op_str'])
                for arg in args:
                    try:
                        if arg.startswith('0x'):
                            target_val = int(arg, 16)
                        elif re.match(r'^[0-9a-f]+$', arg):
                            target_val = int(arg, 16)
                        if target_val is not None:
                            break
                    except ValueError:
                        pass
                    
            if target_val is not None:
                # Check if val is a VMA in our range
                if start_addr <= target_val < end_addr:
                    target_idx = (target_val - start_addr) // CODE_BLOCK_SIZE
                    if target_idx != blk_idx:
                        block['reachable'].add(target_idx)

    # 5a. Report cross-block PC-relative data accesses (literal pools, `adr`,
    # `add rN, pc, #imm`). These are handled transparently at runtime by the
    # BusFault.PRECISERR / MemManage.DACCVIOL recovery paths, so they are NOT
    # build errors. We still log them for visibility — each one will cause a
    # fault + DMA reload at runtime, which has a performance cost.
    if pc_rel_violations:
        print(f"[Protect] NOTE: {len(pc_rel_violations)} cross-block PC-relative data access(es).")
        print("[Protect]       These will trigger runtime fault recovery (data-miss path).")
        for v in pc_rel_violations:
            print(
                f"[Protect]   {v['mnemonic']:6s} at 0x{v['addr']:08x} (block {v['src_blk']})"
                f" -> 0x{v['target']:08x} (block {v['dst_blk']})"
            )

    # 5b. Handle Sequential Fallthrough
    # If a block doesn't end with an Unconditional Branch, execution falls through to the next block.
    # We must mark block I+1 as reachable from I.
    for i in range(num_blocks - 1):
        # Default: Assume fallthrough is needed
        needs_fallthrough = True
        
        block = blocks[i]
        
        # Find the last instruction in this block
        # We need instructions that start in this block
        res_insts = [ins for ins in insts if block['vma_start'] <= ins['addr'] < block['vma_end']]
        
        if res_insts:
            # Sort by addr
            res_insts.sort(key=lambda x: x['addr'])
            last_ins = res_insts[-1]
            
            # Check for Instruction Straddling
            # If start + size > block_end, it definitely needs next block
            if last_ins['addr'] + last_ins['size'] > block['vma_end']:
                needs_fallthrough = True
            else:
                # Check based on Mnemonic
                mnem = last_ins['mnemonic']
                op_str = last_ins['op_str']
                
                # Unconditional Branch List (that DOES NOT return)
                # b, b.n, b.w
                # bx (if not linking)
                # pop {..., pc}
                
                if IS_RISCV:
                    # Unconditional jump or return ends the block's flow; calls
                    # (jal/c.jal) and conditional branches fall through.
                    if mnem in RISCV_UNCOND_MNEMONICS:
                        needs_fallthrough = False
                else:
                    is_uncond_b = mnem in ['b', 'b.n', 'b.w']
                    is_return_pop = 'pop' in mnem and 'pc' in op_str
                    is_return_bx = mnem == 'bx' # usually bx lr

                    if is_uncond_b or is_return_pop or is_return_bx:
                        needs_fallthrough = False
                    
                # Note: 'bl' (Branch with Link) returns, so it FALLS THROUGH effectively.
                # Conditional branches (bne, beq) FALL THROUGH.
        
        if needs_fallthrough:
            block['reachable'].add(i + 1)

    # 6. Encrypt and Pack
    final_blob = b""

    # Layout selection: env vars mirror the kernel's Cargo features.
    #
    #   UMBRA_CHAINED                UMBRA_ESS_MISS_RECOVERY   Layout
    #   0 (legacy)                   0                         [HMAC(32) | Meta(32) | CT(256)]  320B
    #   1                            0                                          [Meta(32) | CT(256)]  288B
    #   1                            1                         [HMAC(32) | Meta(32) | CT(256)]  320B
    chained_mode = os.environ.get("UMBRA_CHAINED", "0") == "1"
    ess_miss_recovery = os.environ.get("UMBRA_ESS_MISS_RECOVERY", "0") == "1"
    META_SIZE = 32
    HMAC_PREFIX_SIZE = 32 if (not chained_mode or ess_miss_recovery) else 0
    HEADER_SIZE = META_SIZE + HMAC_PREFIX_SIZE  # 32 or 64
    # MUST match kernel's `MAX_REACHABLE` in src/kernel/src/common/ess.rs.
    # Kernel asserts `count <= MAX_REACHABLE` on each block's meta and
    # truncates reads to this many entries — host writing more would yield
    # divergent meta interpretation.
    MAX_REACHABLE = 4

    # Seed the running chain key with the master key (matches the kernel's
    # `Kernel::begin_measurement` which copies `master_key::MASTER_KEY`).
    chain_state = master_key

    # Subkey used for the per-block HMAC prefix under ess_miss_recovery. Must
    # stay byte-for-byte in sync with `key_derivation::HMAC_KEY_LABEL` in the
    # boot crate; diverging breaks Task 3A.3's runtime Validator.
    HMAC_KEY_LABEL = b"umbra-hmac-v1"
    per_block_hmac_key = hmac.new(master_key, HMAC_KEY_LABEL, hashlib.sha256).digest()

    mode_label = "chained" if chained_mode else "per-block"
    if ess_miss_recovery:
        mode_label += "+ess_miss_recovery"
    print(f"[Protect] Generating blob with BlockSize={CODE_BLOCK_SIZE}, Header={HEADER_SIZE} ({mode_label})")
    
    if hmac_over_plaintext:
        print("[Protect] --hmac-over-plaintext: ct region carries plaintext, sig binds plaintext")

    # Pass 1: Compute meta + ciphertext + binding_input + (optional) sig for
    # every block in numeric order. These are independent of fold order.
    per_block = []
    for blk in blocks:
        # Encrypt (L552) or pass through plaintext (L562, hmac-over-plaintext).
        if hmac_over_plaintext:
            ciphertext = blk['data']
        else:
            ciphertext = encrypt_block(blk['data'], aes_key)

        # Reachable list — sorted, truncated to MAX_REACHABLE (= kernel's value).
        reachable_list = sorted(list(blk['reachable']))
        if len(reachable_list) > MAX_REACHABLE:
            print(f"WARNING: Block {blk['id']} has too many reachable blocks ({len(reachable_list)}). Truncating.")
            reachable_list = reachable_list[:MAX_REACHABLE]

        meta = struct.pack("B", len(reachable_list))
        for r_idx in reachable_list:
            meta += struct.pack("B", r_idx)
        # Pad metadata to a fixed META_SIZE (32B). Kernel reads 32B per block.
        meta += b'\x00' * (META_SIZE - len(meta))

        # Block-binding input: [block_id_le(4) | ciphertext | meta]. Must match
        # kernel's `verify_slice` in load_and_verify_block byte-for-byte.
        block_id_bytes = struct.pack("<I", blk['id'])
        binding_input = block_id_bytes + ciphertext + meta

        # Per-block HMAC sig. Used in:
        #  - chained_mode + ess_miss_recovery: runtime Validator re-check on ESS miss.
        #  - non-chained: prepended to every block on flash (legacy diff path).
        sig = None
        if chained_mode and ess_miss_recovery:
            sig = hmac.new(per_block_hmac_key, binding_input, hashlib.sha256).digest()
        elif not chained_mode:
            sig = hmac.new(hmac_key, binding_input, hashlib.sha256).digest()

        per_block.append({
            'id': blk['id'],
            'reachable_in_meta': reachable_list,  # truncated, sorted; matches what kernel reads from meta
            'meta': meta,
            'ciphertext': ciphertext,
            'binding_input': binding_input,
            'sig': sig,
            'reachable_display': list(blk['reachable']),
        })

    # Pass 2: Simulate the kernel's BFS fold order. Mirrors api_impl.rs's
    # `umbra_enclave_create_imp` lines 100-159 — start at block 0, walk
    # reachables in meta order (already sorted), skipping visited and
    # out-of-range entries. Folding chain in this order is fix #4 from prior
    # session findings; without it, host folds [0..num_blocks-1] in numeric
    # order while kernel folds only the BFS-reachable subset, causing
    # chained-measurement FAIL whenever the call graph leaves any block
    # un-reached (e.g. prime's block 2 when block 1 ends with `pop {pc}`
    # and has no branch to block 2).
    if chained_mode:
        bfs_visit_order = []
        bfs_visited = {0}
        bfs_queue = [0]
        while bfs_queue:
            idx = bfs_queue.pop(0)
            bfs_visit_order.append(idx)
            for r in per_block[idx]['reachable_in_meta']:
                if r not in bfs_visited and r < num_blocks:
                    bfs_visited.add(r)
                    bfs_queue.append(r)

        for idx in bfs_visit_order:
            chain_state = hmac.new(chain_state, per_block[idx]['binding_input'], hashlib.sha256).digest()

        if bfs_visit_order != list(range(num_blocks)):
            print(f"[Protect] BFS chain fold order: {bfs_visit_order} "
                  f"(numeric would be {list(range(num_blocks))})")
            unreached = sorted(set(range(num_blocks)) - set(bfs_visit_order))
            if unreached:
                print(f"[Protect] Unreached-by-BFS blocks (NOT in chain): {unreached}")

    # Pass 3: Build final_blob in numeric order to match the on-flash layout
    # the kernel expects (block N at flash_offset = header + N * TOTAL_BLOCK_SIZE).
    final_blob = b""
    for entry in per_block:
        if chained_mode and ess_miss_recovery:
            block_blob = entry['sig'] + entry['meta'] + entry['ciphertext']
        elif chained_mode:
            block_blob = entry['meta'] + entry['ciphertext']
        else:
            block_blob = entry['sig'] + entry['meta'] + entry['ciphertext']
        final_blob += block_blob
        print(f"Block {entry['id']}: Size={len(block_blob)}, Reachable={entry['reachable_display']}")
    code_blob_size = len(final_blob)  # encrypted-blocks region; written to header.code_size

    # extract static-PIE relocations.
    # Two reloc families produce slots holding compile-time absolute
    # addresses that the kernel must translate to runtime addresses
    #   - R_ARM_ABS32     → pointer-array initialisers like
    #                       `char const *dict[2279] = {"a","b",...}`
    #   - R_ARM_GOT_BREL  → GOT slots filled with absolute addresses for
    #                       extern symbols (anagram_dictionary, …)
    #
    # Without R_ARM_GOT_BREL coverage, heavy paper-apps MemManage on the
    # first GOT-routed load (R3 ends up holding e.g. 0x2270, the compile-
    # time address of anagram_dictionary, which the next instruction
    # tries to dereference as a runtime pointer → fault outside any
    # enclave).
    #
    # The kernel works with PLAINTEXT-RELATIVE offsets (0-indexed from
    # `_enclave_code_start`, i.e. block 0's first byte), so we translate
    # by subtracting `start_addr` (= the section's VMA, typically 0x30).
    #
    # To resolve GOT_BREL we need to peek at the LITERALS in the
    # unmodified `._enclave_code` plaintext — extract it now (we'll
    # overwrite this section with encrypted content via update_section
    # below, so do it BEFORE that step).
    _tmp_code_path = "_relocs_code_snapshot.bin"
    extract_section(elf_file, "._enclave_code", _tmp_code_path)
    with open(_tmp_code_path, "rb") as f:
        _code_snapshot_bytes = f.read()
    os.remove(_tmp_code_path)
    if IS_RISCV:
        # RISC-V: the only absolute slots are R_RISCV_32 (data pointers/function
        # tables). GOT_HI20/PCREL/CALL_PLT are PC-relative — the whole blob moves
        # together, so they need no fixup. readelf prints each offset as a VMA.
        _rv_relocs = run_cmd([f"{CROSS}readelf", "-W", "-r", elf_file])
        abs32_vmas = sorted({
            int(p[0], 16)
            for line in _rv_relocs.splitlines()
            for p in [line.split()]
            if len(p) >= 3 and p[2] == "R_RISCV_32"
        })
    else:
        abs32_vmas = extract_static_pie_reloc_vmas(
            elf_file, "._enclave_code", start_addr, _code_snapshot_bytes
        )
    # readelf prints each R_ARM_ABS32 offset as a VMA (compile-time virtual
    # address). The kernel works with PLAINTEXT-RELATIVE offsets (0-indexed
    # from `_enclave_code_start`, i.e. block 0's first byte), so we
    # translate by subtracting `start_addr` (= the section's VMA, typically
    # 0x30).
    #
    # The kernel computes `block_idx = O / CODE_BLOCK_SIZE` and
    # `intra = O % CODE_BLOCK_SIZE` to locate each fixup slot at runtime
    # address `(ess_base|0x10000000) + O`. Clamp out any reloc whose
    # translated offset falls past the actual signed code size — those
    # live inside the linker's `.= _enclave_code_start + 0x5000` padding
    # and have no runtime effect, but inflate the table for no reason.
    reloc_entries = []
    for vma in abs32_vmas:
        off = vma - start_addr
        if off < 0 or off >= num_blocks * CODE_BLOCK_SIZE:
            continue
        reloc_entries.append(off)
    reloc_count = len(reloc_entries)
    demand_paging = os.environ.get("UMBRA_DEMAND_PAGING", "0") == "1"
    assert_demand_paging_safe(demand_paging, reloc_count)
    _reloc_family = "R_RISCV_32" if IS_RISCV else "R_ARM_ABS32 + R_ARM_GOT_BREL"
    print(f"[Protect] Static-PIE relocs ({_reloc_family}): "
          f"{reloc_count} entries (plaintext-relative offsets, fixed up at block install).")

    # Pack the reloc table — `[u32 offset_0][u32 offset_1]...`. Append
    # immediately after the encrypted blocks. The kernel locates it at
    # `enclave_flash_base + UMBRA_HEADER_SIZE + header.code_size` and reads
    # `header.reserved1` (renamed reloc_count) entries.
    reloc_table_bytes = b"".join(struct.pack("<I", o) for o in reloc_entries)
    final_blob += reloc_table_bytes

    # Fold the reloc table into the chained measurement so the kernel can
    # detect on-flash tampering of the reloc list. Non-chained mode signs
    # `final_blob` directly (further down) which already includes the table
    # — no extra step needed there.
    if chained_mode and reloc_count > 0:
        chain_state = hmac.new(chain_state, reloc_table_bytes, hashlib.sha256).digest()

    # 7. Write Output to Section
    # Check if it fits? 
    # Current Size capability: The section in ELF is 1024 bytes.
    # New size: NumBlocks * 320.
    # If code is 100 bytes -> 1 Block -> 320 bytes. Fits.
    # If code is 900 bytes -> 4 Blocks -> 1280 bytes. Overflow!
    
    if len(final_blob) > sec_info['size']:
        print(f"WARNING: New enclave size ({len(final_blob)}) exceeds section size ({sec_info['size']}). This may corrupt the binary.")
        # We'll proceed but warn.
        
    out_bin = "enclave_final.bin"
    with open(out_bin, "wb") as f:
        f.write(final_blob)
        
    update_section(elf_file, "._enclave_code", out_bin)
    os.remove(out_bin)
    
    # 8. Update Header (in ELF)
    # We need to find "._enclave_header".
    hdr_info = get_section_info(elf_file, "._enclave_header")
    if hdr_info:
        # We need to patch the HMAC field in the header?
        # "The final result, called measurement, is compared...".
        # Does the header contain the measurement?
        # main.c: "HMAC (32 bytes) - Initialized to zero".
        # This is likely the "Measurement" of the *whole* enclave?
        # Or the HMAC of the first block?
        # Let's compute a "Master HMAC" over the entire final_blob?
        # Or just use the HMAC of the last block (if chained)?
        # In chained mode, the measurement IS the final running chain_state
        # (what the kernel's finalize_measurement() compares against). In
        # non-chained mode the kernel doesn't actually consult this field at
        # runtime, but we still populate it with a stable digest for tooling.
        if chained_mode:
            measurement = chain_state
            # Enclave anti-rollback (gated, default OFF). When UMBRA_VERSION_BIND=1,
            # bind (author_id, version) into the measurement by a trailing fold so the
            # kernel can DERIVE the version (never stored in clear). Default OFF keeps
            # L552/L562/RISC-V blobs byte-identical (their kernels compare the plain
            # chain value).
            if os.environ.get("UMBRA_VERSION_BIND") == "1":
                _author_id = int(os.environ.get("UMBRA_AUTHOR_ID", "0"))
                _enclave_version = int(os.environ.get("UMBRA_ENCLAVE_VERSION", "1"))
                measurement = version_tag(measurement, _author_id, _enclave_version)
        else:
            measurement = hmac.new(hmac_key, final_blob, hashlib.sha256).digest()
        print(f"[Protect] Enclave Measurement ({mode_label}): {measurement.hex()}")
        
        # Read header section
        extract_section(elf_file, "._enclave_header", "header.bin")
        with open("header.bin", "rb") as f:
            hdr_bytes = bytearray(f.read())
        
        # Patch HMAC (last 32 bytes)
        # Struct is 48 bytes.
        if len(hdr_bytes) >= 48:
            # Offset 16 is HMAC
            hdr_bytes[16:48] = measurement

            # Patch Code Size = encrypted-blocks size ONLY (NOT including
            # the appended reloc table). The kernel uses this to compute
            # num_blocks = code_size / TOTAL_BLOCK_SIZE; including reloc
            # bytes here would inflate num_blocks and the BFS loop would
            # walk past the actual block region into the reloc table.
            struct.pack_into("<I", hdr_bytes, 10, code_blob_size)

            # Patch reloc_count into the formerly-reserved1 u16 field at
            # offset 14. The kernel reads (header_flash_base + 48 +
            # code_size) for `reloc_count` u32 entries.
            if reloc_count > 0xFFFF:
                print(f"[Protect] ERROR: reloc_count={reloc_count} exceeds u16 "
                      f"capacity; widen the header field.")
                sys.exit(1)
            struct.pack_into("<H", hdr_bytes, 14, reloc_count)

            # Patch EFBC Size / ESS Blocks if needed
            # For now leave defaults.
            
            with open("header_new.bin", "wb") as f:
                f.write(hdr_bytes)
                
            update_section(elf_file, "._enclave_header", "header_new.bin")
            os.remove("header.bin")
            os.remove("header_new.bin")
            print("[Protect] Updated Enclave Header")
        else:
             print("Error: Header section too small")

    print("[Protect] Done.")

if __name__ == "__main__":
    main()
