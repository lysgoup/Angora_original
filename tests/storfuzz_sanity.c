#include <stdint.h>
#include <stdlib.h>
static volatile uint8_t state = 0;
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    if (n < 4) return 0;
    state = d[0]; state ^= d[1]; state += d[2];
    if (state == 0xAB) abort();
    return 0;
}
