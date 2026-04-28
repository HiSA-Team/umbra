# Hardware Setup

## Selecting the Target MCU

Before building, you must select the target microcontroller in `settings.sh`. Open the file and set the `MCU_VARIANT` variable:

- `stm32l552` — for the NUCLEO-L552ZE-Q board (default)
- `stm32l562` — for the STM32L562E-DK Discovery board

Then source the configuration:

```bash
source settings.sh
```

The script auto-detects which variant is selected and configures feature flags, flash addresses, and peripheral settings accordingly.

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

The L562 Discovery has an on-board Octa-SPI flash. Umbra uses it for storing encrypted enclave binaries. The OTFDEC (On-The-Fly Decryption) engine transparently decrypts data on read.

No additional configuration is needed — `debug.sh` handles programming the external flash.
