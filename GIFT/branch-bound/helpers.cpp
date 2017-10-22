#ifndef __ATTACK_HELPERS__
#define __ATTACK_HELPERS__

#define TINY (6e-50)

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

size_t nibbles(uint64_t a) {
    size_t n = 0;
    for (size_t i = 0; i < sizeof(a) * 2; i++) {
        if (a & 0xf)
            n++;
        a >>= 4;
    }
    return n;
}

unsigned char parity(unsigned char e) {
    e ^= e >> 4;
    e ^= e >> 2;
    e ^= e >> 1;
    return e & 1;
}

size_t parity(size_t e) {
    if (sizeof(size_t) == 8)
        e ^= e >> 32;
    e ^= e >> 16;
    e ^= e >> 8;
    e ^= e >> 4;
    e ^= e >> 2;
    e ^= e >> 1;
    return e & 1;
}

size_t weight(uint64_t a) {
    size_t w = 0;
    for (size_t n = 0; n < sizeof(a) * 8; n++) {
        w += a & 1;
        a >>= 1;
    }
    return w;
}

size_t nibble_weight(uint64_t a) {
    size_t w = 0;
    for (size_t n = 0; n < sizeof(a) * 2; n++) {
        w += (a & 0xf) ? 1 : 0;
        a >>= 4;
    }
    return w;
}

void print_bin(size_t val) {
    size_t msk = 1;
    for (int n = sizeof(size_t) * 8 - 1; n >= 0; n--) {
        if (val & (msk << n)) {
            printf("1");
        } else {
            printf("0");
        }
    }
    printf("\n");
}

#endif
