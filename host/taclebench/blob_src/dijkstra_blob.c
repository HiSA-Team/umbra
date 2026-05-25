// Standalone Umbra enclave blob wrapping TACLeBench `dijkstra`.
// Shortest-path graph algorithm. Smallest of the paper's apps (~300 LOC,
// 2 files: dijkstra.c + input.c). Mentioned in the Umbra paper as
// "the slowest application but also the smallest, making its access
// pattern distribution irrelevant".
//
// Expected R0=0 if dijkstra_return returns 0 (path checksum matches).
extern void dijkstra_init(void);
extern void dijkstra_main(void);
extern int  dijkstra_return(void);

__attribute__((section(".app.enclave_header"), used))
const unsigned char enclave_header[48] = {
    0x55, 0x42, 0x4D, 0x52, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x00, // code_size = 0x400 (patched by protect)
    0x00, 0x00,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

__attribute__((section(".app.enclave_code"), used))
int enclave_entry(void)
{
    dijkstra_init();
    dijkstra_main();
    return dijkstra_return();
}
