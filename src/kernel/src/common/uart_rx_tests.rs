//! Host-side tests for the console UART ownership core (sibling-file pattern).

use super::*;
extern crate std;
use std::vec::Vec;

fn drain(u: &mut ConsoleUart, caller: Owner) -> Vec<u8> {
    core::iter::from_fn(|| u.getc(caller)).collect()
}

#[test]
fn ns_default_owner_reads_in_order() {
    let mut u = ConsoleUart::new();
    for b in b"abc" {
        u.rx_push(*b);
    }
    assert_eq!(drain(&mut u, Owner::Ns), b"abc");
    assert_eq!(u.getc(Owner::Ns), None);
}

#[test]
fn full_buffer_drops_newest_and_counts() {
    let mut u = ConsoleUart::new();
    for i in 0..=RX_CAPACITY {
        u.rx_push(i as u8); // 0..=255, then 0 again as the 257th byte
    }
    assert_eq!(u.overflow(Owner::Ns), Some(1));
    let got = drain(&mut u, Owner::Ns);
    assert_eq!(got.len(), 256);
    assert_eq!((got[0], got[255]), (0, 255));
}

#[test]
fn claimed_uart_delivers_to_enclave_only() {
    let mut u = ConsoleUart::new();
    assert!(u.claim(7).is_ok());
    assert_eq!(u.owner(), Owner::Enclave(7));
    u.rx_push(b'x');
    assert_eq!(u.getc(Owner::Ns), None);
    assert_eq!(u.getc(Owner::Enclave(3)), None);
    assert_eq!(u.getc(Owner::Enclave(7)), Some(b'x'));
}

#[test]
fn claim_on_busy_uart_changes_nothing() {
    let mut u = ConsoleUart::new();
    u.claim(1).unwrap();
    u.rx_push(b'k');
    assert_eq!(u.claim(2), Err(Busy));
    assert_eq!(u.getc(Owner::Enclave(1)), Some(b'k'));
}

#[test]
fn handover_discards_previous_owner_input() {
    let mut u = ConsoleUart::new();
    for _ in 0..=RX_CAPACITY {
        u.rx_push(b'p'); // NS input, one byte over capacity
    }
    u.claim(4).unwrap();
    assert_eq!(u.getc(Owner::Enclave(4)), None);
    assert_eq!(u.overflow(Owner::Enclave(4)), Some(0));
}

#[test]
fn release_returns_uart_to_ns_with_fresh_input() {
    let mut u = ConsoleUart::new();
    u.claim(5).unwrap();
    u.rx_push(b's'); // typed for the enclave
    assert_eq!(u.release(6), Err(NotOwner));
    assert_eq!(u.release(5), Ok(()));
    u.rx_push(b'n');
    assert_eq!(drain(&mut u, Owner::Ns), b"n");
}

#[test]
fn owner_gone_releases_only_the_owner() {
    let mut u = ConsoleUart::new();
    u.claim(8).unwrap();
    u.rx_push(b'q');
    u.owner_gone(9); // some other enclave exits: no effect
    assert_eq!(u.getc(Owner::Enclave(8)), Some(b'q'));
    u.rx_push(b'r');
    u.owner_gone(8); // owner faults
    assert_eq!(u.getc(Owner::Ns), None);
    assert!(u.claim(9).is_ok());
}

#[test]
fn only_the_owner_enclave_transmits_ns_always_does() {
    let mut u = ConsoleUart::new();
    u.claim(2).unwrap();
    assert!(u.may_transmit(Owner::Enclave(2)));
    assert!(!u.may_transmit(Owner::Enclave(3)));
    assert!(u.may_transmit(Owner::Ns));
    assert_eq!(u.overflow(Owner::Enclave(3)), None);
}

#[test]
fn reclaim_by_owner_keeps_its_input() {
    let mut u = ConsoleUart::new();
    u.claim(3).unwrap();
    u.rx_push(b'z');
    assert!(u.claim(3).is_ok());
    assert_eq!(u.getc(Owner::Enclave(3)), Some(b'z'));
}
