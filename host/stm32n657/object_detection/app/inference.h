#ifndef INFERENCE_H
#define INFERENCE_H

/* `.app.enclave_code.entry` is a separate sub-section the linker pulls
 * BEFORE the rest of `.app.enclave_code`, so `run_inference` ends up at
 * offset 0 of `._enclave_code` (= entry point) regardless of how GCC
 * orders any future helpers. */
#define ENCLAVE_ENTRY __attribute__((section(".app.enclave_code.entry")))
#define ENCLAVE_CODE  __attribute__((section(".app.enclave_code")))

/* Error codes */
#define INFER_OK          0
#define INFER_BAD_MAGIC   1
#define INFER_BAD_LEN     2
#define INFER_NPU_TIMEOUT 3

int run_inference(void) ENCLAVE_ENTRY;

#endif
