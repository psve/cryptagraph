#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "helper.cpp"

uint8_t SBOX[] = {
    0x6, 0x5, 0xC, 0xA,
    0x1, 0xE, 0X7, 0x9,
    0xB, 0x0, 0x3, 0xD,
    0x8, 0xF, 0x4, 0x2
};

uint8_t ISBOX[] = {
    0x9, 0x4, 0xF, 0xA,
    0xE, 0x1, 0x0, 0x6,
    0xC, 0x7, 0x3, 0x8,
    0x2, 0xB, 0x5, 0xD
};

uint64_t ShiftRow(uint64_t s) {
    const uint16_t b0 = s & 0xffff;
    const uint16_t b1 = (s >> 16) & 0xffff;
    const uint16_t b2 = (s >> 32) & 0xffff;
    const uint16_t b3 = (s >> 48) & 0xffff;

    uint64_t o;
    o = _rotl(b3, 13);
    o <<= 16;
    o |= _rotl(b2, 12);
    o <<= 16;
    o |= _rotl(b1, 1);
    o <<= 16;
    o |= b0;
    return o;
}

uint64_t InvShiftRow(uint64_t s) {
    const uint16_t b0 = s & 0xffff;
    const uint16_t b1 = (s >> 16) & 0xffff;
    const uint16_t b2 = (s >> 32) & 0xffff;
    const uint16_t b3 = (s >> 48) & 0xffff;

    uint64_t o;
    o = _rotr(b3, 13);
    o <<= 16;
    o |= _rotr(b2, 12);
    o <<= 16;
    o |= _rotr(b1, 1);
    o <<= 16;
    o |= b0;
    return o;
}

uint64_t SubColumn(const uint64_t s) {
    uint64_t o = 0;
    for (size_t n = 0; n < sizeof(s) * 2; n++) {
        uint64_t I;

        I = (s >> n) & 1;
        I <<= 1;
        I |= (s >> (n+16)) & 1;
        I <<= 1;
        I |= (s >> (n+32)) & 1;
        I <<= 1;
        I |= (s >> (n+48)) & 1;

        uint64_t O = SBOX[I];

        o |= (O & 1) << (n + 48);
        O >>= 1;
        o |= (O & 1) << (n + 32);
        O >>= 1;
        o |= (O & 1) << (n + 16);
        O >>= 1;
        o |= (O & 1) << n;

        assert(O < 2);
    }
    return o;
}

uint64_t InvSubColumn(const uint64_t s) {
    uint64_t o = 0;
    for (size_t n = 0; n < sizeof(s) * 2; n++) {
        uint64_t I;

        I = (s >> n) & 1;
        I <<= 1;
        I |= (s >> (n+16)) & 1;
        I <<= 1;
        I |= (s >> (n+32)) & 1;
        I <<= 1;
        I |= (s >> (n+48)) & 1;

        uint64_t O = ISBOX[I];

        o |= (O & 1) << (n + 48);
        O >>= 1;
        o |= (O & 1) << (n + 32);
        O >>= 1;
        o |= (O & 1) << (n + 16);
        O >>= 1;
        o |= (O & 1) << n;

        assert(O < 2);
    }
    return o;
}

void test_cipher() {
    printf("DEBUG: Running cipher tests\n");
    {
        for (uint8_t I = 0; I < 16; I++)
            assert(ISBOX[SBOX[I]] == I);
    }
    {
        for (size_t n = 0; n < 200; n++) {
            auto I = randx();
            auto O = SubColumn(I);
            auto i = InvSubColumn(O);
            assert(i == I);
        }
    }
    {
        for (size_t n = 0; n < 200; n++) {
            auto I = randx();
            auto O = ShiftRow(I);
            auto i = InvShiftRow(O);
            assert(i == I);
        }
    }
}
