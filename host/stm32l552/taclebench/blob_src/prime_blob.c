// Standalone Umbra enclave blob wrapping the TACLeBench `prime` benchmark.
// We call prime_prime directly with the values prime_init would have
// produced (prime_x=2759, prime_y=81 after the swap), bypassing the
// canonical _init/_main/_return triplet whose globals access path is
// currently blocked by the multi-block chain bug surfaced with insertsort.
//
// Algorithmic identity: TACLeBench's prime_main computes
//   prime_result = !(!prime_prime(2759) && !prime_prime(81))
// 2759 = 31 X 89 (composite) and 81 = 3⁴ (composite), so both primality
// checks return 0, and prime_result = !(1 && 1) = 0. We match by
// returning the same expression directly.
extern unsigned char prime_prime(unsigned int n);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, // "UMBR" magic
    0x01,                   // trust_level (Trusted)
    0x00,                   // reserved
    0x01, 0x00,             // efbc_size (1)
    0x00, 0x00,             // ess_blocks
    0x00, 0x02, 0x00, 0x00, // code_size = 0x200 (will be patched by protect)
    0x00, 0x00,             // reserved
    0,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

__attribute__((section(".app.enclave_code"), used)) int enclave_entry(void) {
  unsigned char a = prime_prime(2759); // 31 X 89 → 0
  unsigned char b = prime_prime(81);   // 3⁴   → 0
  return !(!a && !b);                  // 0 on success
}
