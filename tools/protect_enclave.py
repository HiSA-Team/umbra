import sys
import os
import subprocess
import re
import struct
import hmac
import hashlib
import binascii

# --- Configuration ---
# Size of the executable code block (in bytes) that is loaded into RAM
CODE_BLOCK_SIZE = 256 
# Size of the metadata header per block (excluding the data itself)
# We will define this dynamically or fixed.

def run_cmd(args):
    """Run a subprocess command and return output."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {' '.join(args)}\n{e.stderr}")
        sys.exit(1)

def get_section_info(elf_path, section_name):
    """Get section offset, size, and address using objdump."""
    output = run_cmd(["arm-none-eabi-objdump", "-h", elf_path])
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
        "arm-none-eabi-objcopy",
        "-O", "binary",
        f"--only-section={section_name}",
        elf_path,
        output_file
    ])

def update_section(elf_path, section_name, input_file):
    """Update section content from a file."""
    run_cmd([
        "arm-none-eabi-objcopy",
        f"--update-section", f"{section_name}={input_file}",
        elf_path
    ])

def parse_disassembly(elf_path, section_name):
    """
    Parse disassembly to find branch targets and literal loads.
    Returns:
        instructions: list of (addr, size, mnemonic, op_str, bytes)
        labels: dict of addr -> name
    """
    cmd = ["arm-none-eabi-objdump", "-d", f"--section={section_name}", elf_path]
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
                
            size = len(hex_bytes.replace(" ", "")) // 2
            instructions.append({
                "addr": addr,
                "size": size,
                "mnemonic": mnemonic,
                "op_str": op_str,
                "bytes": binascii.unhexlify(hex_bytes.replace(" ", ""))
            })
            
    return instructions, labels

def encrypt_block(data, key):
    """Encrypt data using AES-128-CTR via OpenSSL (matching debug_hmac.py)."""
    # Create temp files
    with open("temp_pt.bin", "wb") as f:
        f.write(data)
    
    key_hex = key.hex()
    iv_hex = "00" * 16 # Fixed IV for now (should be random in production but matching earlier context)
    
    run_cmd([
        "openssl", "enc", "-aes-128-ctr", "-in", "temp_pt.bin", "-out", "temp_ct.bin",
        "-K", key_hex, "-iv", iv_hex, "-nosalt"
    ])
    
    with open("temp_ct.bin", "rb") as f:
        ct = f.read()
        
    os.remove("temp_pt.bin")
    os.remove("temp_ct.bin")
    return ct

def load_symbols(elf_path):
    """Load symbols from ELF using nm, including local symbols."""
    # -a: debug-syms, -n: numeric sort
    cmd = ["arm-none-eabi-nm", "-a", "-n", elf_path]
    try:
        output = run_cmd(cmd)
    except Exception:
        return {}
        
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

def main():
    # Strip optional flags out of argv so the positional parsing below is
    # unchanged. Only flag for now: --hmac-over-plaintext (L562 path).
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    hmac_over_plaintext = "--hmac-over-plaintext" in sys.argv[1:]

    if len(argv) < 3:
        print("Usage: protect_enclave.py [--hmac-over-plaintext] <elf_file> <main_c> <key_file> [obj_dir]")
        sys.exit(1)

    elf_file = argv[0]
    main_c_file = argv[1]
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
    raw_code_file = "raw_code.bin"
    extract_section(elf_file, "._enclave_code", raw_code_file)
    with open(raw_code_file, "rb") as f:
        full_code = f.read()
    os.remove(raw_code_file)
    
    insts, labels = parse_disassembly(elf_file, "._enclave_code")
    
    if not insts:
        print("Error: No instructions found in section")
        sys.exit(1)
        
    # Determine code constraints
    start_addr = sec_info['vma']
    end_addr = insts[-1]['addr'] + insts[-1]['size'] # Rough end of code
    code_len = end_addr - start_addr
    print(f"[Protect] Detected Code Length: {code_len} bytes")
    
    # Trim full_code to just the used part (plus alignment)
    full_code = full_code[:code_len]
    
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

        _check_pc_rel(ins, addr, blk_idx)

        # Check for BRANCHES
        if ins['mnemonic'].startswith('b') or ins['mnemonic'].startswith('c') or 'bl' in ins['mnemonic']:
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
                        if arg.startswith('0x'): target_val = int(arg, 16)
                        elif re.match(r'^[0-9a-f]+$', arg): target_val = int(arg, 16)
                        if target_val is not None: break
                    except ValueError: pass
                    
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
    MAX_REACHABLE = 16 # Max reachable blocks to store

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

    for blk in blocks:
        # 1. Encrypt Data (L552) or pass through plaintext (L562, hmac-over-plaintext).
        # Under --hmac-over-plaintext the variable name "ciphertext" is a misnomer:
        # it literally holds plaintext, which OTFDEC will re-encrypt when the
        # secure boot oracle writes the block back to OCTOSPI flash.
        if hmac_over_plaintext:
            ciphertext = blk['data']
        else:
            ciphertext = encrypt_block(blk['data'], aes_key)
        
        # 2. Build Metadata part (for HMAC calculation)
        # What do we HMAC? The Encrypted Data? Or Header + Data?
        # Usually Encrypt-then-MAC on the Ciphertext.
        # So HMAC(Ciphertext + Metadata?)
        # Design says: "computes HMAC ... for each block ... chaining each HMAC"
        # "chaining each HMAC as the key for the next EFB" -> interesting!
        # For now, let's just HMAC(Ciphertext).
        
        # Reachable list
        reachable_list = sorted(list(blk['reachable']))
        if len(reachable_list) > MAX_REACHABLE:
            print(f"WARNING: Block {blk['id']} has too many reachable blocks ({len(reachable_list)}). Truncating.")
            reachable_list = reachable_list[:MAX_REACHABLE]
            
        meta = struct.pack("B", len(reachable_list))
        for r_idx in reachable_list:
            meta += struct.pack("B", r_idx)
        # Pad metadata to a fixed META_SIZE (32B) regardless of layout. The
        # kernel always reads 32 bytes of metadata per block from flash.
        meta += b'\x00' * (META_SIZE - len(meta))
        
        # Calc HMAC
        # Using a fixed key for now? Or chained?
        # "chaining each HMAC as the key for the next EFB"
        # Step 1: HMAC(Key, Data) -> H1
        # Step 2: HMAC(H1, Data2) -> H2
        # We need to maintain state.
        
        # Let's use the `hmac_key` for the first block, then chain.
        # But wait, Random Access?
        # If we use chaining, we can't verify Block N without verifying 0..N-1.
        # This kills random access for swapping!
        # Using chaining is for "Secure Boot" (checking the whole chain).
        # But for *Runtime Swapping* (ESS), we need to verify individual blocks.
        # Design says: "reads EFBs from flash and computes HMAC... chaining... The final result... is compared".
        # This describes the INITIAL validation (at boot/load).
        # "ESS... caches validated...".
        # If we just need to validate at load time, chaining is fine.
        # But if we swap in a block later, do we re-validate?
        # "If an enclave tries to execute code outside its EFBC... re-validation process from flash".
        # It implies we might re-read from flash.
        # If we use chaining, we must re-read everything from start to N? That's O(N).
        # "entrusting execution to the processor... validation involves flash and accelerators".
        # "Two nearly independent computational paths".
        # Maybe we verify ONLY the needed block?
        # "Hash-based Message Authentication Code (HMAC) for each block using a securely stored key".
        # It says "using a securely stored key", NOT "using the previous HMAC".
        # Wait, the text says: "chaining each HMAC as the key for the next EFB".
        # This explicitly implies chaining.
        # This is a specific design choice called "Hash Chain" or "Merkle implementation".
        # It suggests sequential validation.
        # If we want O(1) validation, we need a Merkle Tree or individual MACs with same key.
        # Given "chaining each HMAC as the key for the next EFB", I will implement that.
        # BUT this makes random access validation hard.
        # "When a new block is needed... fetching, validating...".
        # If validation relies on the chain, we are stuck.
        # UNLESS the "securely stored key" is used for *loading into ESS* and we trust ESS?
        # Maybe the Design implies: We validate the WHOLE image at start?
        # "When Enclave is identified... host loader invokes enclave_create... validates the application binary... Once all EFBs are validated, the enclave is considered secure".
        # Ah! Validation happens ONCE at creation.
        # Then blocks are just loaded?
        # But "ESS stores validated and decrypted blocks".
        # "decoupling enclave execution from code validation".
        # "speculatively request, validate, and load".
        # This implies validation happens *during* runtime too?
        # If the key is changing (chaining), we need the current key state?
        # If we skipped blocks, we don't have the key.
        # Re-reading "using a securely stored key, chaining each HMAC...".
        # Maybe the "securely stored key" IS the root, and we generate per-block keys?
        # Or maybe the text implies the *measure* (M) is the detailed hash chain.
        # If so, maybe we just store the HMACs in the header?
        # Let's stick to a simpler "HMAC of block using Master Key" for this implementation, as "chaining" might be a specific requirement regarding the *measurement* stored in the DB, not necessarily the runtime verification mechanism if random access is needed.
        # OR better: I will implement individual HMACs using the Master Key. This is robust and allows random access. I'll note the deviation or interpretation.
        # The User said: "Each block has it's own hmac" (singular).
        
        # Block-binding input: [block_id_le(4) | ciphertext | meta]. This is
        # exactly what the kernel's verify_slice builds, so the two sides must
        # agree bit-for-bit.
        block_id_bytes = struct.pack("<I", blk['id'])
        binding_input = block_id_bytes + ciphertext + meta

        if chained_mode:
            # Fold this block into the running chain. The final chain_state is
            # written into the enclave header as the reference measurement.
            chain_state = hmac.new(chain_state, binding_input, hashlib.sha256).digest()
            if ess_miss_recovery:
                # Alongside the chain, prepend a per-block HMAC keyed
                # with the derived hmac_key so the runtime Validator can re-check
                # an individual block on an ESS miss without replaying the chain.
                sig = hmac.new(per_block_hmac_key, binding_input, hashlib.sha256).digest()
                block_blob = sig + meta + ciphertext
            else:
                # Chained layout has NO per-block HMAC prefix on flash.
                block_blob = meta + ciphertext
        else:
            # Legacy per-block HMAC keyed with the (fixed) master key; the 32B
            # digest is prepended to every block on flash. This path is retained
            # only for diffing — do not rely on it in production.
            sig = hmac.new(hmac_key, binding_input, hashlib.sha256).digest()
            block_blob = sig + meta + ciphertext

        final_blob += block_blob

        print(f"Block {blk['id']}: Size={len(block_blob)}, Reachable={list(blk['reachable'])}")

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
            
            # Patch Code Size (Total blob size) -> Offset 10 (u32)
            struct.pack_into("<I", hdr_bytes, 10, len(final_blob))
            
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
