#include <stdint.h>

__attribute__((noinline)) static int transform(int value) {
    volatile uint32_t cell = (uint32_t)value;
    if ((cell & 1U) != 0U) {
        cell = cell * 3U + 2U;
    } else {
        cell = cell / 2U;
    }
    return (int)(cell ^ 0x5AU);
}

int main(void) {
    return transform(41) == ((41 * 3 + 2) ^ 0x5A) ? 0 : 1;
}
