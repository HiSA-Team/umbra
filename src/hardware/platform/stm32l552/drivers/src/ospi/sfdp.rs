#![cfg(feature = "stm32l562")]
#![allow(dead_code, unused_imports)]

//! Serial Flash Discoverable Parameters (SFDP) — placeholder.
//! The current bringup path hard-codes MX25LM51245G geometry (64 MB, 4 KB
//! sectors, 256-byte pages) directly in `init.rs`/`transfer.rs` because the
//! L562E-DK ships a single SKU. Reserved for a future flash-agnostic
//! bringup that issues `SFDP_READ` (0x5A) and parses the JEDEC
//! Basic Flash Parameter Table.
