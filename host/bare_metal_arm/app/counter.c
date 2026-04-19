#define ENCLAVE_CODE __attribute__((section(".app.enclave_code")))

int counter_main(void) ENCLAVE_CODE;

int counter_main(void) {
    volatile int count = 0;
    for (int i = 0; i < 100000; i++) {
        count++;
    }
    return count;
}
