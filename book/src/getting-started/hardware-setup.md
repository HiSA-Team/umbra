# Hardware Setup

## Selecting the Target MCU

Set `MCU_VARIANT` near the top of `settings.sh` (or export it before
sourcing) to one of:

- `stm32l552` — for the NUCLEO-L552ZE-Q board
- `stm32l562` — for the STM32L562E-DK Discovery board
- `stm32n657` — for the NUCLEO-N657X0-Q board

Then source the configuration:

```bash
source settings.sh
```

The script configures feature flags, flash addresses, peripheral
settings, OpenOCD config, and the UART baud rate accordingly.

## STM32L552 — NUCLEO-L552ZE-Q

1. Connect the Nucleo board via USB (ST-Link)
2. UART debug is on **LPUART1** via ST-Link VCP (9600 baud)
3. No additional wiring required

### Enable TrustZone

TrustZone must be enabled once via STM32 Programmer:

```bash
make enable_security
```

This sets the TZEN option byte. The device resets after programming.

## STM32L562 — STM32L562E-DK

1. Connect the Discovery board via USB (ST-Link)
2. UART debug is on **USART1** (PA9/PA10) via ST-Link VCP (9600 baud)
3. The on-board MX25LM51245G OCTOSPI flash is used for enclave storage

### Enable TrustZone

Same as L552:

```bash
make enable_security
```

### External Flash

The L562 Discovery has an on-board Octa-SPI flash. Umbra uses it for
storing encrypted enclave binaries. The OTFDEC (On-The-Fly Decryption)
engine transparently decrypts data on read.

No additional configuration is needed — `debug.sh` handles programming
the external flash.

## STM32N657 — NUCLEO-N657X0-Q

1. Connect the Nucleo board via USB (CN1, ST-Link).
2. UART debug is on **USART1** (PE5 = TX, PE6 = RX, AF7) routed to the
   ST-Link VCP at **115200 baud**.
3. Boot mode is set by the **JP2 (BOOT1)** jumper:

   | Position | Mode | Use |
   |---|---|---|
   | 2-3 | Dev-Boot | Before running `flash_n657.sh` — Boot ROM accepts unsigned/UART download |
   | 1-2 | Flash-Boot | After flashing — Boot ROM loads the signed FSBL from XSPI2 |

4. The on-board MX25UM51245G XSPI2 flash (512 Mb) holds the FSBL at
   `0x70000000`, the host bin at `0x70080000`, the enclave header at
   `0x70090000`, and (for the NPU demo) model bytecode + weights
   further up.

There is no `make enable_security` step for the N6: TrustZone is
always active and Boot ROM authenticates the FSBL on every reset. In
BSEC-open (development) state, the signing-tool header is sufficient;
no provisioned key is required.

### Flash workflow

```bash
# 1. JP2 → 2-3 (Dev-Boot) before plugging in
source settings.sh    # MCU_VARIANT=stm32n657
./rebuild_all.sh
tools/flash_n657.sh
# 2. JP2 → 1-2 (Flash-Boot)
# 3. Reset board — Umbra FSBL boots, banner on USART1 @ 115200
```

### Debug after Boot ROM hands off

OpenOCD + GDB cannot reset the M55 cleanly because Boot ROM holds the
core until it has authenticated and copied the FSBL. The recommended
flow is to **let Boot ROM run** and then attach GDB without reset:

```bash
openocd -f openocd_scripts/stm32n6x.cfg          # in one terminal
arm-none-eabi-gdb path/to/boot \
    -ex 'target extended-remote :3333'           # attach, no `monitor reset`
```

The board must be in Flash-Boot mode for this. Symbols load from the
ELF, but execution has already advanced past Boot ROM into the FSBL.
