
//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>                       //
//         Salvatore Bramante <salvatore.bramante@imtlucca.it>                      //
//                                                                                  //
// Description:                                                                     //
//      This is the main file for Secure Boot, implementing the core function       //
//      secure_boot(). Its primary role is to initialize secure memory regions      //
//      and peripherals, with its implementation tailored to the specific platform. //
//      This version is designed for the STM32L552 microcontroller.                 //
//      Additionally, this project handles the setup of peripheral handlers,        //
//      while base handlers, including the vector table, are defined in the         //
//      architecture-specific crate.                                                //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

#![no_main]
#![no_std]

use core::arch::global_asm;
// Local Modules

// Platform-related crates
use arm::sau;
use arm::mpu;
use drivers::gtzc;
use drivers::rcc;
use drivers::uart;
use drivers::uart::Uart;
use drivers::gpio;
use drivers::aes::AesEngine;

// Umbra Kernel-related crates
use kernel::memory_protection_server::memory_guard::MemorySecurityGuardTrait;
use kernel::common::memory_layout::MemoryBlockList;
use kernel::common::memory_layout::MemoryBlockSecurityAttribute;
use crate::secure_kernel::Kernel;

mod crypto_impl;
mod secure_kernel;
mod api_impl;

mod handlers;
mod master_key;
mod key_derivation;
mod validator;
mod prefetch;

#[cfg(feature = "benchmark")]
mod benchmark;

// Global statics for Kernel dependencies
static mut GLOBAL_CRYPTO: Option<crypto_impl::UmbraCryptoEngine> = None;

static mut GLOBAL_GUARDS: [&'static mut dyn MemorySecurityGuardTrait; 0] = [];

// 16 KB BSS buffer for the OTFDEC ENC-mode cipher pass.
// Placed in BSS (not on the stack) because _SECURE_KERNEL_DATA_MEMORY_ is 56 KB
// and a 16 KB stack buffer would likely overflow the secure-boot stack at reset.
// 64 KB would exceed the 56 KB data region — do not increase past 0x4000.
#[cfg(feature = "stm32l562")]
const OTFDEC_REGION_SIZE_BSS: usize = 0x4000; // 16 KB
#[cfg(feature = "stm32l562")]
static mut PLAINTEXT_BUF: [u8; OTFDEC_REGION_SIZE_BSS] = [0u8; OTFDEC_REGION_SIZE_BSS];
#[cfg(feature = "stm32l562")]
static mut CIPHERTEXT_BUF: [u8; OTFDEC_REGION_SIZE_BSS] = [0u8; OTFDEC_REGION_SIZE_BSS];




#[inline(never)]
fn print_hex(_uart: &Uart, val: u32) {
    handlers::print_hex(val);
}

extern "C" {
    static _umb_stack_size: u32;
    static _umb_estack: u32;
    static _host_stack_size: u32; // Assuming this is available just like _host_entry_point
}

#[no_mangle]
pub unsafe fn secure_boot() -> !{
    // Enable GPIO
    // Enable GPIO
    let rcc = rcc::Rcc::new();
    
    // Choose LED Pin based on board
    // STM32L552 Nucleo: PB7 (Blue)
    // STM32L562 Discovery: PD3 (Red)
    #[cfg(feature = "stm32l562")]
    let (periph, port, pin) = (rcc::Peripherals::GPIOD, gpio::Port::GpioD, 3);
    
    #[cfg(not(feature = "stm32l562"))]
    let (periph, port, pin) = (rcc::Peripherals::GPIOB, gpio::Port::GpioB, 7);

    rcc.enable_clock(periph);
    let gpio_led = gpio::Gpio::new(port);
    gpio_led.set_mode(pin, gpio::PinMode::Output);
    
    // Initialize UART (LPUART1 for 552, USART1 for 562)
    let serial = uart::Uart::new_lpuart1_and_configure(9600);
    
    serial.write("\n");
    serial.write("   ___       ___       ___       ___       ___   \n");
    serial.write("  /\\__\\     /\\__\\     /\\  \\     /\\  \\     /\\  \\  \n");
    serial.write(" /:/ _/_   /::L_L_   /::\\  \\   /::\\  \\   /::\\  \\ \n");
    serial.write("/:/_/\\__\\ /:/L:\\__\\ /::\\:\\__\\ /::\\:\\__\\ /::\\:\\__\\\n");
    serial.write("\\:\\/:/  / \\/_/:/  / \\:\\::/  / \\;:::/  / \\/\\::/  /\n");
    serial.write(" \\::/  /    /:/  /   \\::/  /   |:\\/__/    /:/  / \n");
    serial.write("  \\/__/     \\/__/     \\/__/     \\|__|     \\/__/  \n");
    serial.write("\n");
    

    serial.write("[UMBRASecureBoot] Secure Boot started\n");

    // Print Stack Sizes and Usage
    let umb_stack_size_val = &_umb_stack_size as *const u32 as u32;
    let umb_estack_val = &_umb_estack as *const u32 as u32;

    // Calculate current stack usage (sp)
    let sp: u32;
    core::arch::asm!("mov {}, sp", out(reg) sp);
    let used_stack = umb_estack_val - sp;
    
    // Attempting to print using simple hex loop to avoid trait issues if Uart doesn't implement it perfectly
    serial.write("[UMBRASecureBoot] Stack Info:\n");
    
    serial.write("  _umb_stack_size: 0x");
    print_hex(&serial, umb_stack_size_val);
    serial.write("\n");

    serial.write("  Current Secure Stack Usage: 0x");
    print_hex(&serial, used_stack);
    serial.write(" (SP: 0x");
    print_hex(&serial, sp);
    serial.write(")\n");
    
    let remaining_stack = umb_stack_size_val - used_stack;
    serial.write("  Remaining Secure Stack: 0x");
    print_hex(&serial, remaining_stack);
    serial.write("\n");


    serial.write("[UMBRASecureBoot] TEST HAL\n");

    #[cfg(feature = "stm32l562")]
    {
        gpio_led.pin_set(pin);
        serial.write("[UMBRASecureBoot] TEST GPIO Active Low\n");
        gpio_led.pin_reset(pin);
    }
    #[cfg(not(feature = "stm32l562"))]
    {
        gpio_led.pin_reset(pin);
        serial.write("[UMBRASecureBoot] TEST GPIO Active High\n");
        gpio_led.pin_set(pin);
    }
    

    //////////////////////////////
    // INITIALIZE MEMORY GUARDS //
    //////////////////////////////
    
    let mut sau_driver : sau::SauDriver = sau::SauDriver::new();
    serial.write("[UMBRASecureBoot] SAU started\n");

    rcc.enable_clock(rcc::Peripherals::GTZC);
    let mut gtzc_driver : gtzc::GtzcDriver = gtzc::GtzcDriver::new();
    serial.write("[UMBRASecureBoot] GTZC started\n");

    sau_driver.memory_security_guard_init();
    gtzc_driver.memory_security_guard_init();

    // Enable SecureFault (SHCSR.SECUREFAULTENA = bit 19) and MemManage
    // (MEMFAULTENA = bit 16). Without SECUREFAULTENA a secure-state
    // instruction fetch into an MPCBB-NS slot would escalate to HardFault
    // and bypass the Rust `umbra_secure_fault_handler` / ESS-miss recovery
    // path.
    #[cfg(feature = "ess_miss_recovery")]
    {
        let shcsr = 0xE000ED24 as *mut u32;
        let before = core::ptr::read_volatile(shcsr);
        serial.write("[UMBRASecureBoot] SHCSR before: 0x");
        print_hex(&serial, before);
        serial.write("\n");
        // 16=MEMFAULTENA, 17=BUSFAULTENA, 18=USGFAULTENA, 19=SECUREFAULTENA.
        // Enabling BUS/USG prevents silent escalation so a misrouted fault
        // surfaces in its own handler instead of the HardFault sink.
        core::ptr::write_volatile(shcsr, before | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19));
        let after = core::ptr::read_volatile(shcsr);
        serial.write("[UMBRASecureBoot] SHCSR after:  0x");
        print_hex(&serial, after);
        serial.write("\n");
    }

    // Ensure UsageFault is always enabled (needed for enclave
    // termination detection even without ess_miss_recovery).
    unsafe {
        let shcsr = 0xE000ED24 as *mut u32;
        let val = core::ptr::read_volatile(shcsr);
        if (val & (1 << 18)) == 0 {
            core::ptr::write_volatile(shcsr, val | (1 << 18));
        }
    }

    let mut mpu_driver = mpu::MpuDriver::new();
    mpu_driver.init();
    // MAIR0 attr 0 = Normal memory, Outer+Inner WB-WA Non-transient (0xFF).
    // RLAR writes that leave AttrIndx=0 (the default in configure_region and
    // in the raw MPU writes in api_impl.rs) pick this attribute. Without this
    // step attr 0 is 0x00 (Device-nGnRnE), and Cortex-M33 treats stack access
    // to Device memory as CONSTRAINED UNPREDICTABLE — the enclave's first
    // `push {r7, lr}` faults with MemManage.DACCVIOL even though the region
    // AP bits permit the write.
    mpu_driver.set_mair(0, 0xFF);
    mpu_driver.enable();
    serial.write("[UMBRASecureBoot] MPU started\n");

    // MPU Test: Configure Region 0 for 0x20008000 - 0x2000803F as RW
    let mut region_config = mpu::MpuRegionConfig::new();
    region_config.rnum = 0;
    region_config.base_addr = 0x20008000;
    region_config.limit_addr = 0x2000803F;
    region_config.ap = mpu::MpuAccessPermission::RWPrivilegedOnly;
    region_config.sh = mpu::MpuShareability::NonShareable;
    region_config.xn = mpu::MpuExecuteNever::ExecutionPermitted;
    region_config.enable = true;
    
    mpu_driver.configure_region(&region_config);
    serial.write("\t[UMBRASecureBoot] MPU Region 0 Configured: 0x20008000 (RW Priv)\n");
    
    
    //////////////////////////////////////////////////
    // CONFIGURE NON-SECURE CODE - FLASH CONTROLLER //
    //////////////////////////////////////////////////

    // The flash controller is initially configured offline at the bank level. 
    // Currently, 0x08000000 is designated as watermarked (i.e., secure), 
    // while 0x08040000 is non-watermarked, making it non-secure. 
    // Pages (2 KB each) within non-watermarked blocks can be selectively modified to be secure.

    /////////////////////////////////////
    // CONFIGURE NON-SECURE CODE - SAU //
    /////////////////////////////////////

    let mut memory_block_list = MemoryBlockList::create_from_range(0x08040000,0x08080000);
    memory_block_list.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
    sau_driver.memory_security_guard_create(&memory_block_list);
    serial.write("\t[UMBRASecureBoot] Untrusted Memory Block Range: 0x08040000 - 0x08080000\n");

    /////////////////////////////////////
    // CONFIGURE NON-SECURE DATA - SAU //
    /////////////////////////////////////

    // Let's use region 1 to split SRAM1
    // 0x20000000 - 0x20020000: Non-Secure (Host)
    // 0x20020000 - 0x20030000: Secure (EFBC)
    
    // SAU: Mark Host region as Untrusted
    memory_block_list = MemoryBlockList::create_from_range(0x20000000,0x20020000);
    memory_block_list.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
    sau_driver.memory_security_guard_create(&memory_block_list);

    /////////////////////////////////////////////////
    // CONFIGURE NON-SECURE DATA - SRAM CONTROLLER //
    /////////////////////////////////////////////////

    // GTZC: Mark Host region as Untrusted
    memory_block_list = MemoryBlockList::create_from_range(0x20000000,0x20020000);
    memory_block_list.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
    gtzc_driver.memory_security_guard_create(&memory_block_list);

    // GTZC: Mark EFBC region as Trusted
    memory_block_list = MemoryBlockList::create_from_range(0x20020000,0x20030000);
    memory_block_list.set_memory_block_security(MemoryBlockSecurityAttribute::Trusted);
    gtzc_driver.memory_security_guard_create(&memory_block_list);

    // SRAM2 (ESS) - Already correct?
    // See memory.ld in host/
    memory_block_list = MemoryBlockList::create_from_range(0x20030000,0x2003E000);
    memory_block_list.set_memory_block_security(MemoryBlockSecurityAttribute::Trusted);
    gtzc_driver.memory_security_guard_create(&memory_block_list);
    serial.write("\t[UMBRASecureBoot] Trusted Memory Block Range: 0x20020000 - 0x2003E000\n");



    ///////////////////////////////////
    // CONFIGURE NON-SECURE CALLABLE //
    ///////////////////////////////////

    // Configure the non-secure callable region here
    memory_block_list = MemoryBlockList::create_from_range(0x08030000,0x0803ffe0);
    memory_block_list.set_memory_block_security(MemoryBlockSecurityAttribute::TrustedGateway);
    sau_driver.memory_security_guard_create(&memory_block_list);
    serial.write("\t[UMBRASecureBoot] Trusted Gateway Memory Block Range:0x08030000 - 0x0803ffe0\n");

    /////////////////////////////////////
    // DMA Demo                        //
    /////////////////////////////////////
    rcc.enable_clock(rcc::Peripherals::DMA1);
    rcc.enable_clock(rcc::Peripherals::DMA2);
    serial.write("[UMBRASecureBoot] TEST DMA\n");
    
    // Enable NVIC for DMA1 Channel 1 (IRQ 29)
    // Enable NVIC for DMA1 Channels 1-4 (IRQ 29, 30, 31, 32)
    unsafe {
        let nvic_iser0 = 0xE000E100 as *mut u32;
        let nvic_iser1 = 0xE000E104 as *mut u32;
        // IRQ 29, 30, 31 in ISER0
        *nvic_iser0 |= (1 << 29) | (1 << 30) | (1 << 31);
        // IRQ 32 in ISER1 (Bit 0)
        *nvic_iser1 |= (1 << 0);
        
        // Enable Global Interrupts
        core::arch::asm!("cpsie i");
    }
    
    /////////////////////////////////////
    // CONFIGURE NON-SECURE PERIPHERALS - SAU //
    /////////////////////////////////////
    // We must explicitly mark the Non-Secure Peripheral range (0x40000000 - 0x5FFFFFFF) as Non-Secure in SAU.
    // Otherwise, CPU treats accesses as Secure, causing Secure Fault from Non-Secure world.
    // Range: 0x40000000 - 0x4FFFFFFF (Peripherals on AHB/APB)
    memory_block_list = MemoryBlockList::create_from_range(0x40000000, 0x50000000);
    memory_block_list.set_memory_block_security(MemoryBlockSecurityAttribute::Untrusted);
    sau_driver.memory_security_guard_create(&memory_block_list);
    serial.write("\t[UMBRASecureBoot] Untrusted Peripheral Range: 0x40000000 - 0x50000000\n");


    /////////////////////////////////////
    // HASH HMAC TEST                  //
    /////////////////////////////////////
    serial.write("[UMBRASecureBoot] TEST HASH\n");

    use drivers::hash::{Hash, Algorithm, DataType};
    let mut hash = Hash::new();
    let key = "test".as_bytes();
    let data = "ForzaNapoliSempre".as_bytes();
    let mut ctx = hash.start(Algorithm::SHA256, DataType::Width8, Some(key));
    hash.update(&mut ctx, data);
    let mut digest = [0u8; 32];
    hash.finish(ctx, &mut digest);

    serial.write("\t[HMAC] SHA256: ");
    handlers::print_hex_bytes(&digest);
    serial.write("\n");
    
    /////////////////////////////////////
    // AES TEST                        //
    /////////////////////////////////////
    serial.write("[UMBRASecureBoot] TEST AES\n");
    {
        #[cfg(feature = "stm32l562")]
        use drivers::aes::AesHardware as AesImpl;
        
        #[cfg(not(feature = "stm32l562"))]
        use drivers::aes::AesEmulated as AesImpl;
        
        let mut aes = AesImpl::new();
        let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let input: [u8; 16] = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
        let expected_ciphertext: [u8; 16] = [0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97];
        
        let mut output: [u8; 16] = [0; 16];
        let mut check_decrypt: [u8; 16] = [0; 16];

        #[cfg(feature = "stm32l562")]
        serial.write("\t[AES] Does AES-128 HW Test.. \n");
        #[cfg(not(feature = "stm32l562"))]
        serial.write("\t[AES] Does AES-128 SW Test.. \n");

        aes.init(&key, None);
        aes.encrypt_block(&input, &mut output);
        
        serial.write("\t[AES] Encrypted: ");
        handlers::print_hex_bytes(&output);
        serial.write("\n");

        if output == expected_ciphertext {
            serial.write("\t[AES] Encryption MATCH\n");
        } else {
             serial.write("\t[AES] Encryption FAIL\n");
        }

        aes.decrypt_block(&output, &mut check_decrypt);
        
        if check_decrypt == input {
             serial.write("\t[AES] Decryption MATCH\n");
        } else {
             serial.write("\t[AES] Decryption FAIL\n");
        }
    }

    //////////////////////////////
    // INITIALIZE SECURE KERNEL //
    //////////////////////////////
    unsafe {
        // Initialize Hash driver
        let hash_driver = drivers::hash::Hash::new();
        
        // Initialize AES driver
        #[cfg(feature = "stm32l562")]
        use drivers::aes::AesHardware as AesImpl;
        #[cfg(not(feature = "stm32l562"))]
        use drivers::aes::AesEmulated as AesImpl;
        
        let aes_driver = AesImpl::new();
        
        GLOBAL_CRYPTO = Some(crypto_impl::UmbraCryptoEngine::new(hash_driver, aes_driver));

        let crypto_engine = GLOBAL_CRYPTO.as_mut().unwrap();
        let guards = &mut GLOBAL_GUARDS;

        let kernel = Kernel::new(guards, Some(crypto_engine));
        Kernel::init(kernel);
        if let Some(k) = Kernel::get() {
            k.init_keys();
        }
        serial.write("[UMBRASecureBoot] Kernel Initialized\n");
    }

    //////////////////////////////////////////
    // OCTOSPI1 bringup                     //
    //////////////////////////////////////////
    // Disabled in benchmark builds: the OTFDEC + OCTOSPI three-phase
    // cipher/program/verify path costs ~2 KB of secure-boot flash and
    // pushes `_SECURE_BOOT_TEXT_MEMORY_` into overflow on L562 once the
    // benchmark module is also linked in. The benchmark uses static
    // test vectors in `.rodata`, not flash-backed enclave blocks, so
    // OTFDEC is not needed for the miss measurements. The load-time
    // S3 boot measurement on L562 will therefore reflect the early
    // failure of `umbra_tee_create_imp` rather than a full chain verify.
    #[cfg(all(feature = "stm32l562", not(feature = "benchmark")))]
    {
        use drivers::ospi::{OspiDriver, OCTOSPI_MEMMAP_BASE};

        let ospi = OspiDriver::new();
        ospi.init();
        match ospi.enable_memory_mapped_octa() {
            Ok(()) => {
                serial.write("[UMBRASecureBoot] OCTOSPI memory-mapped OK\n");
            }
            Err(msg) => {
                serial.write("[UMBRASecureBoot] OCTOSPI FAIL: ");
                serial.write(msg);
                serial.write("\n");
                loop { core::hint::spin_loop(); }
            }
        }

        // Dump first 16 bytes at 0x9000_0000 for the Stage 1 gate.

        use drivers::ofd::{OfdDriver, Region, KeyMode, Config as OfdConfig};
        const OTFDEC_REGION_SIZE: usize = 0x4000; // 16 KB
        const OTFDEC_NUM_SECTORS: usize = OTFDEC_REGION_SIZE / 0x1000; // 4
        const OTFDEC_NUM_PAGES:   usize = OTFDEC_REGION_SIZE / 256;    // 64
        const OTFDEC_NUM_WORDS:   usize = OTFDEC_REGION_SIZE / 4;      // 4096

        // Unrecoverable failure sink on any error in cipher/program/verify.
        // The downstream boot will never reach NS and the lack of "Jumping to
        // Non-Secure World" on UART is the signal.
        let s2_fail = |_serial: &uart::Uart| -> ! {
            loop { core::hint::spin_loop(); }
        };

        // Defensive OTFDEC reset. OTFDEC key/config registers survive any
        // reset short of POR, so if a previous boot left Region 1 enabled
        // and KEYLOCK'd, the "plaintext oracle" read below would actually
        // read OTFDEC-decrypted garbage and silently poison the whole
        // three-phase cipher. A soft REG_EN clear is ignored once the
        // region is locked, so pulse RCC.AHB2RSTR.OTFDEC1RST to wipe the
        // peripheral back to reset state.
        rcc.reset_otfdec();

        // Derive OTFDEC region key + nonce from MASTER_KEY via HMAC-SHA256.
        // Needed by both cold and warm paths, so derive before branching.
        // Re-borrowing GLOBAL_CRYPTO here aliases the &mut held by Kernel, but
        // init_keys() has already returned and no NS code is running yet, so
        // the aliasing window is a single-threaded boot-time read.
        let raw = key_derivation::derive_otfdec_raw(GLOBAL_CRYPTO.as_mut().unwrap());
        let mut otfdec_key = [0u8; 16];
        let mut otfdec_nonce = [0u8; 8];
        let mut i = 0;
        while i < 16 { otfdec_key[i] = raw[i]; i += 1; }
        let mut i = 0;
        while i < 8 { otfdec_nonce[i] = raw[16 + i]; i += 1; }

        // Build a reusable config template; flip only `enable` at each call site.
        let ofd_cfg = |enable: bool| OfdConfig {
            start_addr: OCTOSPI_MEMMAP_BASE,
            end_addr:   OCTOSPI_MEMMAP_BASE + (OTFDEC_REGION_SIZE as u32) - 1,
            nonce: otfdec_nonce, key: otfdec_key,
            mode: KeyMode::InstructionAndData, enable,
        };

        // Cold-vs-warm flash probe. OTFDEC is now reset, so the mm-READ shows
        // raw flash bytes. Cold flash (fresh enclaves_plain.bin) → UBMR magic.
        // Warm flash (previous boot already wrote ciphertext) → other.
        const UBMR_MAGIC_LE: u32 = 0x524D4255;
        let probe_word = core::ptr::read_volatile(OCTOSPI_MEMMAP_BASE as *const u32);
        let mut ofd = OfdDriver::new();

        if probe_word == UBMR_MAGIC_LE {
            // ============ COLD PATH: full three-phase cipher cycle ============
            // Oracle: buffer plaintext from flash (mm-READ; OTFDEC off).
            for i in 0..OTFDEC_REGION_SIZE {
                PLAINTEXT_BUF[i] = core::ptr::read_volatile(
                    (OCTOSPI_MEMMAP_BASE + i as u32) as *const u8
                );
            }

            // ---- SRAM->SRAM cipher via OTFDEC ENC----
            ofd.set_enciphering(true);
            ofd.configure_region(Region::Region1, ofd_cfg(true));
            if !ofd.is_region_enabled(Region::Region1) { s2_fail(&serial); }
            for i in 0..OTFDEC_NUM_WORDS {
                let mm_addr = (OCTOSPI_MEMMAP_BASE as usize) + i * 4;
                let pt_word = core::ptr::read_unaligned(
                    (PLAINTEXT_BUF.as_ptr() as usize + i * 4) as *const u32,
                );
                core::ptr::write_volatile(mm_addr as *mut u32, pt_word);
                let ct_word = core::ptr::read_volatile(mm_addr as *const u32);
                core::ptr::write_unaligned(
                    (CIPHERTEXT_BUF.as_mut_ptr() as usize + i * 4) as *mut u32,
                    ct_word,
                );
            }
            // RM0438: CR.ENC writable only when all regions disabled.
            ofd.configure_region(Region::Region1, ofd_cfg(false));
            ofd.set_enciphering(false);

            // ---- erase + indirect-program ciphertext----
            rcc.reset_ospi();
            ospi.init();
            if ospi.disable_memory_mapped().is_err() { s2_fail(&serial); }
            for s in 0..OTFDEC_NUM_SECTORS {
                if ospi.sector_erase_4k((s * 0x1000) as u32).is_err() { s2_fail(&serial); }
            }
            rcc.reset_ospi();
            ospi.init();
            for p in 0..OTFDEC_NUM_PAGES {
                let off = p * 256;
                let slice = core::slice::from_raw_parts(
                    CIPHERTEXT_BUF.as_ptr().add(off),
                    256,
                );
                if ospi.page_program(off as u32, slice).is_err() { s2_fail(&serial); }
                rcc.reset_ospi();
                ospi.init();
            }

            // ---- mm-READ + OTFDEC DEC verify ----
            rcc.reset_ospi();
            ospi.init();
            if ospi.enable_memory_mapped_octa().is_err() { s2_fail(&serial); }
            ofd.configure_region(Region::Region1, ofd_cfg(true));

            let mut verify_pass = true;
            for i in 0..OTFDEC_NUM_WORDS {
                let got = core::ptr::read_volatile(
                    ((OCTOSPI_MEMMAP_BASE as usize) + i * 4) as *const u32,
                );
                let want = core::ptr::read_unaligned(
                    (PLAINTEXT_BUF.as_ptr() as usize + i * 4) as *const u32,
                );
                if got != want { verify_pass = false; break; }
            }
            if !verify_pass { s2_fail(&serial); }
        } else {
            // ============ WARM PATH: ciphertext already on flash ============
            // Previous boot wrote the ciphertext; all we need is to
            // re-engage OTFDEC Region 1 DEC with the same derived key and
            // confirm the mm-READ decrypts back to UBMR.
            ofd.set_enciphering(false);
            ofd.configure_region(Region::Region1, ofd_cfg(true));
            if !ofd.is_region_enabled(Region::Region1) { s2_fail(&serial); }

            let dec_word = core::ptr::read_volatile(OCTOSPI_MEMMAP_BASE as *const u32);
            if dec_word != UBMR_MAGIC_LE { s2_fail(&serial); }
        }
    }

    // Configure Secure SysTick (disabled until enclave_enter enables it).
    unsafe {
        let syst_csr = 0xE000_E010 as *mut u32;
        core::ptr::write_volatile(syst_csr, 0x00); // Ensure disabled
    }
    serial.write("[UMBRASecureBoot] SysTick configured (disabled)\n");

    /////////////////////////////////////
    // Configure VTOR and MSP_NS       //
    /////////////////////////////////////

    rcc::Rcc::set_vtor_ns(0x08040000);

    /////////////////////////////////////
    // Jump to Non-Secure World        //
    /////////////////////////////////////
    serial.write("[UMBRASecureBoot] Jumping to Non-Secure World\n");

    // Benchmark runs only on warm resets (NRST pin, software, watchdog).
    // On a cold power-on/brown-out reset the normal boot continues into
    // the non-secure world, so the first boot after flashing is always
    // "production". To execute the benchmark, press the reset button
    // after the board has cold-booted once.
    #[cfg(feature = "benchmark")]
    {
        const RCC_CSR: *mut u32 = 0x5002_1094 as *mut u32;
        const BORRSTF_BIT: u32 = 1 << 27; // POR / brown-out reset
        const RMVF_BIT:    u32 = 1 << 23; // Remove reset flags

        let csr = unsafe { core::ptr::read_volatile(RCC_CSR) };
        let is_cold_boot = (csr & BORRSTF_BIT) != 0;
        unsafe { core::ptr::write_volatile(RCC_CSR, csr | RMVF_BIT); }

        if is_cold_boot {
            serial.write("[UMBRASecureBoot] Cold boot: skipping benchmark (press reset to run)\n");
        } else {
            serial.write("[UMBRASecureBoot] Warm reset: running benchmark\n");
            benchmark::run_all(&serial);
        }
    }

    trampoline_to_ns();

    loop {}

}


#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    // The trampoline function is used to jump to the
    // host entry point, which is defined in the linker
    // script.
    pub fn trampoline_to_ns();
}
#[cfg(all(target_arch = "arm", target_os = "none"))]
global_asm!(
    "
    .section .text
    .global trampoline_to_ns
    .extern _host_entry_point     

    trampoline_to_ns:
        ldr r0, =0x20020000
        msr MSP_NS, r0
        ldr r0, =_host_entry_point      // Load the address of ns_fn 
        movs r1, #1
        bics r0, r1                     // Clear bit 0 of address in r0 
        blxns r0                        // Branch to the non-secure function 

    "
);


// Synchronization for DMA Tests
static mut DMA_COMPLETED: bool = false;

#[no_mangle]
pub extern "Rust" fn is_dma_complete() -> bool {
    unsafe { core::ptr::read_volatile(&DMA_COMPLETED) }
}

#[no_mangle]
pub extern "Rust" fn reset_dma_complete() {
    unsafe { core::ptr::write_volatile(&mut DMA_COMPLETED, false); }
}

#[no_mangle]
pub extern "C" fn DMA1_Channel1_Handler() { handle_dma_irq(0); }
#[no_mangle]
pub extern "C" fn DMA1_Channel2_Handler() { handle_dma_irq(1); }
#[no_mangle]
pub extern "C" fn DMA1_Channel3_Handler() { handle_dma_irq(2); }
#[no_mangle]
pub extern "C" fn DMA1_Channel4_Handler() { handle_dma_irq(3); }
#[no_mangle]
pub extern "C" fn DMA1_Channel5_Handler() { handle_dma_irq(4); }
#[no_mangle]
pub extern "C" fn DMA1_Channel6_Handler() { handle_dma_irq(5); }
#[no_mangle]
pub extern "C" fn DMA1_Channel7_Handler() { handle_dma_irq(6); }
#[no_mangle]
pub extern "C" fn DMA1_Channel8_Handler() { handle_dma_irq(7); }

fn handle_dma_irq(ch_idx: u32) {
    unsafe { DMA_COMPLETED = true; }

    unsafe {
        let dma1_ifcr = 0x50020004 as *mut u32;
        *dma1_ifcr = 0xF << (ch_idx * 4);
    }
    
}

