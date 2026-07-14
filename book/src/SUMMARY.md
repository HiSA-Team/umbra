# Summary

[Introduction](introduction.md)

---

# Getting Started

- [Prerequisites](getting-started/prerequisites.md)
- [Build and Run](getting-started/build-and-run.md)
- [Hardware Setup](getting-started/hardware-setup.md)

# Host Examples

- [Overview](examples/README.md)
- [Bare-Metal](examples/bare-metal.md)
- [FreeRTOS](examples/freertos.md)
- [Tock](examples/tock.md)
- [NPU Object Detection](examples/object-detection.md)

# Architecture

- [Overview](architecture/overview.md)
- [Crate Structure](architecture/crate-structure.md)
- [HAL Traits](architecture/hal-traits.md)
- [Type-State Security Domain](architecture/type-state.md)
- [Error Handling](architecture/error-handling.md)
- [The umbra-api Leaf Crate](architecture/api-crate.md)
- [Boot Flow](architecture/boot-flow.md)
- [FSBL Boot (STM32N6)](architecture/fsbl-boot.md)
- [Enclave Swap Space](architecture/ess-model.md)

# Design Decisions

- [Overview](decisions/README.md)
- [ADR 000 — Threat Model](decisions/000-threat-model.md)
- [ADR 001 — Workspace Layout](decisions/001-workspace-layout.md)
- [ADR 002 — UmbraError](decisions/002-umbra-error.md)
- [ADR 003 — HAL Trait Surface](decisions/003-hal-traits.md)
- [ADR 004 — Type-State Security Domain](decisions/004-type-state-security-domain.md)
- [ADR 005 — NSC Boundary](decisions/005-nsc-boundary.md)
- [ADR 006 — Master-Key Chain of Trust](decisions/006-master-key-chain.md)
- [ADR 007 — Panic Policy](decisions/007-panic-policy.md)
- [ADR 008 — RISC-V SPMP Arbitration](decisions/008-riscv-spmp-arbitration.md)
- [ADR 009 — State Continuity Power-Session Boundary](decisions/009-state-continuity-power-session-boundary.md)
- [ADR 010 — State-Continuity Commit (root-in-anchor)](decisions/010-state-continuity-commit-reconciliation.md)
- [ADR 011 — Enclave Eviction Feasibility](decisions/011-enclave-eviction-feasibility.md)

# Supported Hardware

- [STM32L552 Nucleo](hardware/stm32l552.md)
- [STM32L562 Discovery](hardware/stm32l562.md)
- [STM32N657 Nucleo](hardware/stm32n657.md)

# API Reference

- [NSC Veneers](api/nsc-veneers.md)

# Porting

- [Porting to a New Board](porting/porting-a-new-board.md)

# Formal Verification

- [ProVerif Models](formal/proverif.md)

# Contributing

- [Overview](contributing.md)
- [Guardrails](contributing/guardrails.md)
  - [NEVER_DO](contributing/never-do.md)
  - [ALWAYS_DO](contributing/always-do.md)
  - [Code Review Checklist](contributing/code-review-checklist.md)
