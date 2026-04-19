# Already done
- [x] Enclave creation and execution
- [x] Secure Boot
- [x] Memory Protection through SAU and MPU
- [x] HASH driver for HMAC computation
- [x] AES driver for encryption/decryption
- [x] DMA driver for data transfer
- [x] RCC driver for clock control
- [x] GPIO driver for GPIO control
- [x] LPUART driver for LPUART and UART communication
- [x] GTZC driver for GTZC and SAU configuration
- [x] MPU driver for MPU configuration
- [x] Enclave header



# TODO

## STM32l562 port:
- [ ] Octospi to support external flash memory
## kernel structure:
- [ ] Improve Binary loaders in kernel
- [ ] Improve Key Generation
## Binary Deployment:
- [ ] Create a CLI tool to deploy non-secure binaries to the target and split it into EFBs
- [ ] Change load_and_verify_block with dma