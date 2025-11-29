#include "fibonacci.h"
#include <stdint.h>


// TBD...
__attribute__((section(".app.enclave_header")))
const uint8_t enclave_header[16] = {
    0x55, 0x42, 0x4D, 0x52,  // Magic: "UMBR" in little-endian
    0x01,                    // Trust_level (Trusted)
    0x00,                    // reserved
    0x01, 0x00,              // efbc_size (1)
    0x00, 0x00,              // ess_blocks 
    0x08, 0x00, 0x00, 0x00,  // code_size (8 byte)
    0x00, 0x00               // reserved
};
__attribute__((section(".app.enclave_code")))
__attribute__((naked))
unsigned int simple_enclave(void) {
    __asm volatile (
        "mov r0, #42\n"
        "bx lr\n" 
    );
}

extern unsigned int umbra_tee_create();
extern unsigned int umbra_enclave_run();

int main(){
    
    fibonacci();
    unsigned int enclave_id = umbra_tee_create();
    unsigned int result = umbra_enclave_run();
    while(1);

    return 0;
}
