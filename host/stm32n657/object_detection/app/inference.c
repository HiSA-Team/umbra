#include "inference.h"
#include <stdint.h>

#define INFER_MAGIC 0x554D4231u  /* 'UMB1' little-endian */
#define IMAGE_LEN   150528u      /* 224 * 224 * 3 */
#define OUTPUT_LEN_TOTAL 1470u   /* full Tiny YOLO v2 output: 7×7×5×6 INT8 */

/* Output region per regenerated network.c's LL_ATON_Output_Buffers_Info:
 *   .addr_base    = 0x342E0000  (Secure AXISRAM5)
 *   .offset_start = 26560 (0x67C0)
 *   .offset_end   = 28030  (length 1470 bytes = 1×7×7×30 INT8 YOLO output)
 * Full output address: 0x342E67C0. Activations span 0x342E0000-0x34335C00
 * (343 KB, all in MPU R8 unpriv RW XN). */
#define OUTPUT_OFFSET 26560u
#define OUTPUT_LEN    1470u

#define INPUT_SHARED_HDR   ((volatile uint32_t *)0x24080000u)
#define INPUT_SHARED_IMAGE ((volatile uint8_t  *)0x24080010u)
#define OUTPUT_SHARED_HDR  ((volatile uint32_t *)0x240C0000u)
#define OUTPUT_SHARED_BYTES ((volatile uint8_t *)0x240C0000u)

/* Secure-aliased NPU activations region. MPU R8 makes this RW unpriv;
 * NPU bus master (Sec/Priv/CID=1 per RIMC + SECCFGR3 bit 10) sees the
 * same addresses. */
#define NPU_ACTIVATIONS_BASE ((volatile uint8_t *)0x342E0000u)

/* NPU register block — Secure alias (NS 0x480E... gets dropped by the
 * RM0486 §6.3.4 "secure guard" since RISUP 106 = Secure-only).
 *
 * EPC0 register layout (RM0486 §20.5 + ATON.h):
 *   +0x00 CTRL     bit 0 = EN, bit 1 = CLR, bit 30 = CONFCLR, bit 31 = RUNNING (RO)
 *   +0x08 ADDR     bytecode start (8-byte aligned)
 *   +0x0C IRQ      W1C event flags
 *   +0x10 ENCR_LSB encryption key low 32
 *   +0x14 ENCR_MSB encryption key high + EN bit 12 + KEY_SEL
 *   +0x18 CID_CACHE  EC's bus master CID
 * Subsystem-wide registers:
 *   CLKCTRL.CTRL=0x580E0000  AGATES0=+0x08  AGATES1=+0x0C  BGATES=+0x10
 *   INTCTRL.CTRL=0x580E1000  INTORMSK0=+0x14  INTANDMSK0=+0x24
 *   BUSIF[0].CTRL=0x580E2000  BUSIF[1].CTRL=0x580E3000 */
#define EPC_BASE      ((volatile uint8_t  *)0x580FE000u)
#define EPC_CTRL      ((volatile uint32_t *)(EPC_BASE + 0x0))
#define EPC_ADDR      ((volatile uint32_t *)(EPC_BASE + 0x8))
#define EPC_IRQ       ((volatile uint32_t *)(EPC_BASE + 0xC))
#define EPC_ENCR_LSB  ((volatile uint32_t *)(EPC_BASE + 0x10))
#define EPC_ENCR_MSB  ((volatile uint32_t *)(EPC_BASE + 0x14))
#define EPC_CID_CACHE ((volatile uint32_t *)(EPC_BASE + 0x18))
#define EPC_CTRL_CLR_BIT      (1u << 1)
#define EPC_CTRL_CONFCLR_BIT  (1u << 30)
#define EPC_CTRL_EN_BIT       (1u << 0)
#define EPC_CTRL_RUNNING_BIT  (1u << 31)

#define ATON_CLKCTRL_CTRL_REG   ((volatile uint32_t *)0x580E0000u)
#define ATON_CLKCTRL_AGATES0    ((volatile uint32_t *)0x580E0008u)
#define ATON_CLKCTRL_AGATES1    ((volatile uint32_t *)0x580E000Cu)
#define ATON_CLKCTRL_BGATES     ((volatile uint32_t *)0x580E0010u)
#define ATON_INTCTRL_CTRL_REG   ((volatile uint32_t *)0x580E1000u)
#define ATON_INTCTRL_INTORMSK0  ((volatile uint32_t *)0x580E1014u)
#define ATON_INTCTRL_INTANDMSK0 ((volatile uint32_t *)0x580E1024u)
#define ATON_BUSIF0_CTRL        ((volatile uint32_t *)0x580E2000u)
#define ATON_BUSIF1_CTRL        ((volatile uint32_t *)0x580E3000u)

#define MODEL_BYTECODE_ADDR 0x70200000u

int run_inference(void) {
    /* Validate input header. */
    if (INPUT_SHARED_HDR[0] != INFER_MAGIC) return INFER_BAD_MAGIC;
    if (INPUT_SHARED_HDR[1] != IMAGE_LEN)   return INFER_BAD_LEN;

    /* Copy 224×224×3 image bytes from NS shared buffer into the Secure
     * NPU activations region. MAIR0=Device-nGnRnE keeps these writes
     * unbuffered/uncached so the NPU sees them immediately. */
    for (uint32_t i = 0; i < IMAGE_LEN; i++) {
        NPU_ACTIVATIONS_BASE[i] = INPUT_SHARED_IMAGE[i];
    }

    /* One-time NPU subsystem bring-up — mirrors `LL_ATON_Init` from
     * Middlewares/.../ll_aton.c. Idempotent across enclave re-entries. */
    *ATON_CLKCTRL_CTRL_REG = (1u << 1);   /* CTRL.CLR=1 — reset pipeline */
    *ATON_CLKCTRL_CTRL_REG = 1u;          /* CTRL.EN =1 — master clock on */
    *ATON_CLKCTRL_AGATES0  = 0xFFFFFFFFu;
    *ATON_CLKCTRL_AGATES1  = 0xFFFFFFFFu;
    *ATON_BUSIF0_CTRL      = 1u;          /* bus master 0 on */
    *ATON_BUSIF1_CTRL      = 1u;          /* bus master 1 on */
    *ATON_INTCTRL_CTRL_REG = 1u;

    /* INTCTRL masks per upstream LL_ATON_RT_RuntimeInit: OR-path masks
     * stream-engine events (bits 0..9), AND-path masks everything. */
    *ATON_INTCTRL_INTORMSK0  = 0x000003FFu;
    *ATON_INTCTRL_INTANDMSK0 = 0xFFFFFFFFu;

    /* Enable ALL leaf clocks. The EC's bytecode issues configuration-network
     * writes to many downstream units (STRSWITCH, STRENG0-9, CONVACC0-3,
     * ACTIV/ARITH/POOL). If any target unit is clock-gated, the EC stalls
     * waiting for a response. */
    *ATON_CLKCTRL_BGATES = 0xFFFFFFFFu;

    *EPC_IRQ = 0u;                        /* clear any latched flags */
    *EPC_CID_CACHE = 1u;                  /* tag EC bus txns with Secure CID */

    /* "Clean the internal NPU state" per RM0486 §3.5.5 — EPC-level
     * CLR pulse (drain pipeline) then CONFCLR pulse (wipe config). HW
     * auto-clears each bit when the pulse completes. */
    *EPC_CTRL = EPC_CTRL_CLR_BIT;
    while (*EPC_CTRL & EPC_CTRL_CLR_BIT) { }
    *EPC_CTRL = EPC_CTRL_CONFCLR_BIT;
    while (*EPC_CTRL & EPC_CTRL_CONFCLR_BIT) { }

    /* Defensive: zero encryption registers. ENCR_MSB.EN (bit 12)
     * defaults to 0 (bypass), but §3.5.5 mandates re-programming
     * keys before tenant use. */
    *EPC_ENCR_LSB = 0u;
    *EPC_ENCR_MSB = 0u;

    /* Kick: CTRL=0 (default with SM=0 continuous mode), ADDR=blob,
     * CTRL.EN=1 to start. HW sets RUNNING (bit 31) on start. */
    *EPC_CTRL = 0u;
    *EPC_ADDR = MODEL_BYTECODE_ADDR;
    *EPC_CTRL = EPC_CTRL_EN_BIT;

    /* Poll RUNNING — the EC halts at every microinstruction step boundary
     * with EPC.IRQ asserted, and we W1C-clear it inline to release the
     * halt. The runtime's full async state machine is the canonical sync
     * mechanism; inline polling works because we bypass it (see project
     * memory note for the architectural ceiling at ~9s wall time). */
    uint32_t timeout = 100000000u;
    while ((*EPC_CTRL & EPC_CTRL_RUNNING_BIT) != 0u && timeout > 0u) {
        timeout--;
        uint32_t irq = *EPC_IRQ;
        if (irq) {
            *EPC_IRQ = irq;
        }
    }

    if (timeout == 0u) {
        OUTPUT_SHARED_HDR[0] = (uint32_t)INFER_NPU_TIMEOUT;
        return INFER_NPU_TIMEOUT;
    }

    /* Copy the full 1470-byte NPU output (7×7×30 INT8 Tiny YOLO v2 tensor)
     * from AXISRAM5 0x342E67C0 into the NS shared buffer at OUTPUT_SHARED_BYTES
     * + 64 (= out_hdr[16] aligned). Host-side post-processor decodes this
     * into person detections (dequantize + sigmoid + NMS). */
    for (uint32_t i = 0; i < OUTPUT_LEN_TOTAL; i++) {
        OUTPUT_SHARED_BYTES[64 + i] = NPU_ACTIVATIONS_BASE[OUTPUT_OFFSET + i];
    }

    OUTPUT_SHARED_HDR[0] = (uint32_t)INFER_OK;
    return INFER_OK;
}
