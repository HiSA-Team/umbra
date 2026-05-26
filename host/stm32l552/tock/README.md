# Tock host port — STM32L552

Tock kernel as an Umbra Non-Secure host. Umbra Secure programs the NS-MPU
during boot; this port wires Tock with the `NoopMpu` stub so Tock never
touches the MPU.

## Build

```bash
source ./settings.sh stm32l552
export HOST_APP=tock
./rebuild_all.sh
```

Output: `host/stm32l552/tock/bin/tock.elf` (kernel + apps + bundled
fibonacci enclave merged).

## Flash + run

```bash
./debug.sh
```

UART output on `/dev/cu.usbmodem*` @ 9600 baud (board's onboard ST-Link
VCOM).

## TACLeBench harness

```bash
HOST_APP=tock PHASE5_BENCHES=binarysearch ./tools/test_taclebench.sh
HOST_APP=tock PHASE5_BENCHES=paper ./tools/test_taclebench.sh
```

## Submodule pins

- `lib/tock` — Tock kernel @ `b35fad8` master plus a vendor patch on
  `MuxUart::do_next_op` (commit `3f61f85f`) for sync-callback ordering.
- `lib/libtock-rs` — userspace runtime @ `0766d8c`.
- `rust-toolchain.toml` — `nightly-2026-05-19`.
