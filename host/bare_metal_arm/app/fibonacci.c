#include "fibonacci.h"

// Demo enclave payload. Linked into `.app.enclave_code` and loaded by secure
// boot via the EFB pipeline. `fibonacci()` returns 1925854120; the
// `dummy_filler_*` functions exist only to push the code size past one EFB
// block so the multi-block loader path gets exercised.

// Section attribute for all enclave code
#define ENCLAVE_CODE __attribute__((section(".app.enclave_code")))

int fibonacci() ENCLAVE_CODE;
int heavy_computation(int val) ENCLAVE_CODE;
void dummy_filler_A(int *val) ENCLAVE_CODE;
void dummy_filler_B(int *val) ENCLAVE_CODE;
void dummy_filler_C(int *val) ENCLAVE_CODE;

// A large function to consume space (approx 100+ bytes)
int heavy_computation(int val) {
  volatile int x = val;
  x = x * 1664525 + 1013904223;
  x = (x << 13) ^ x;
  x = x * 1664525 + 1013904223;
  if (x % 2 == 0)
    x += 1;
  else
    x -= 1;
  x = x * 1664525 + 1013904223;
  x = (x << 13) ^ x;
  return x;
}

// Filler to push code size
void dummy_filler_A(int *val) {
  *val += 1;
  *val = heavy_computation(*val);
  *val ^= 0xAAAAAAAA;
  *val = heavy_computation(*val);
}

void dummy_filler_B(int *val) {
  *val += 2;
  *val = heavy_computation(*val);
  *val ^= 0x55555555;
  *val = heavy_computation(*val);
}

void dummy_filler_C(int *val) {
  *val += 3;
  *val = heavy_computation(*val);
  *val ^= 0xFF00FF00;
  *val = heavy_computation(*val);
}

int fibonacci() {
  int n = 12;
  int t1 = 0, t2 = 1;
  int nextTerm = t1 + t2;

  // Call functions that are likely in different blocks due to size
  t1 = heavy_computation(t1);
  dummy_filler_A(&t1);

  t2 = heavy_computation(t2);
  dummy_filler_B(&t2);

  for (int i = 3; i <= n; ++i) {
    t1 = t2;
    t2 = nextTerm;

    // More calls inside loop
    dummy_filler_C(&t1);

    if (t1 > 100000)
      t1 = 0; // Prevent overflow

    nextTerm = t1 + t2;
  }

  return nextTerm; // Expected : 1925854120
}