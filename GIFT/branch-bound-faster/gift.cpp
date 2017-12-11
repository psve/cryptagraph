#include <stdint.h>
#include <stdlib.h>

#ifndef __CIPHER__
#define __CIPHER__

#define CIPHER_SIZE (64)        // bit-size
#define CIPHER_SBOX_SIZE (4)    // bit-size
#define CIPHER_SBOX_VALUES (16) // combinatorial

uint64_t const SBOX[CIPHER_SBOX_VALUES] = {
    0x1, 0xa, 0x4, 0xc,
    0x6, 0xf, 0x3, 0x9,
    0x2, 0xd, 0xb, 0x7,
    0x5, 0x0, 0x8, 0xe
};

uint64_t const PERM[CIPHER_SIZE] = {
    0x0000000000000001L,
    0x0000000000020000L,
    0x0000000400000000L,
    0x0008000000000000L,
    0x0001000000000000L,
    0x0000000000000002L,
    0x0000000000040000L,
    0x0000000800000000L,
    0x0000000100000000L,
    0x0002000000000000L,
    0x0000000000000004L,
    0x0000000000080000L,
    0x0000000000010000L,
    0x0000000200000000L,
    0x0004000000000000L,
    0x0000000000000008L,
    0x0000000000000010L,
    0x0000000000200000L,
    0x0000004000000000L,
    0x0080000000000000L,
    0x0010000000000000L,
    0x0000000000000020L,
    0x0000000000400000L,
    0x0000008000000000L,
    0x0000001000000000L,
    0x0020000000000000L,
    0x0000000000000040L,
    0x0000000000800000L,
    0x0000000000100000L,
    0x0000002000000000L,
    0x0040000000000000L,
    0x0000000000000080L,
    0x0000000000000100L,
    0x0000000002000000L,
    0x0000040000000000L,
    0x0800000000000000L,
    0x0100000000000000L,
    0x0000000000000200L,
    0x0000000004000000L,
    0x0000080000000000L,
    0x0000010000000000L,
    0x0200000000000000L,
    0x0000000000000400L,
    0x0000000008000000L,
    0x0000000001000000L,
    0x0000020000000000L,
    0x0400000000000000L,
    0x0000000000000800L,
    0x0000000000001000L,
    0x0000000020000000L,
    0x0000400000000000L,
    0x8000000000000000L,
    0x1000000000000000L,
    0x0000000000002000L,
    0x0000000040000000L,
    0x0000800000000000L,
    0x0000100000000000L,
    0x2000000000000000L,
    0x0000000000004000L,
    0x0000000080000000L,
    0x0000000010000000L,
    0x0000200000000000L,
    0x4000000000000000L,
    0x0000000000008000L,
};

uint64_t permute(uint64_t x){
    uint64_t out = 0;
    for (size_t i = 0 ; i < CIPHER_SIZE ; i++) {
        out |= x & 1 ? PERM[i] : 0;
        x >>= 1;
    }
    return out;
}

#endif
