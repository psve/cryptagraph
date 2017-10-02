#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

void bin(const uint64_t v) {
    uint64_t m = 1L << (sizeof(v) * 8 - 1);
    for (;m;m >>= 1) {
        printf("%u", m & v ? 1 : 0);
    }
}

// for unit testing

uint64_t randx() {
    uint64_t o = 0;
    o ^= rand();
    o <<= 32;
    o ^= rand();
    return o;
}

// left rotations

uint16_t _rotl(const uint16_t value, int shift) {
    return (value << shift) | (value >> (sizeof(value)*8 - shift));
}

uint64_t _rotl(const uint64_t value, int shift) {
    return (value << shift) | (value >> (sizeof(value)*8 - shift));
}

unsigned int _rotl(const unsigned int value, int shift) {
    return (value << shift) | (value >> (sizeof(value)*8 - shift));
}

// right rotations

uint16_t _rotr(const uint16_t value, int shift) {
    return (value >> shift) | (value << (sizeof(value)*8 - shift));
}

uint64_t _rotr(const uint64_t value, int shift) {
    return (value >> shift) | (value << (sizeof(value)*8 - shift));
}

unsigned int _rotr(const unsigned int value, int shift) {
    return (value >> shift) | (value << (sizeof(value)*8 - shift));
}
