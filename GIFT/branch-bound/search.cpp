#ifndef __ATTACK_BRANCH_BOUND__
#define __ATTACK_BRANCH_BOUND__

#include "cipher.cpp"
#include "analysis.cpp"

#include <utility>
#include <iostream>

/*
 *
 */
double branch_bound_fill(
    uint64_t& result,  // best round trail
    std::vector<approx_t> (&approxes) [CIPHER_SBOX_VALUES], // elp approx
    size_t rounds,     // number of rounds to search
    double bound,      // elp, lower bound (for rounds)
    size_t round,      // current round number
    double elp,        // elp
    uint64_t pin,      // input parity
    uint64_t pout,     // temp, initally 0
    size_t n
) {
    static const size_t Sboxes = CIPHER_SIZE / CIPHER_SBOX_SIZE;

    assert(n <= Sboxes);
    assert(round <= rounds);

    static_assert(CIPHER_SBOX_SIZE == 4, "currently assumes 4-bit sbox");

    for (; n < Sboxes; n++) {

        // fetch input parity

        auto val_in = (pin >> (n * CIPHER_SBOX_SIZE)) & 0xf; // 4-bits
        if (val_in == 0)
            continue;

        // pick approximations

        for (auto const &approx: approxes[val_in]) {
            assert(approx.input == val_in);

            // check bound

            auto new_elp = elp * approx.corr;
            if (new_elp <= bound)
                continue;

            // fill sbox approximation

            auto mask = approx.output << (n * CIPHER_SBOX_SIZE);
            bound = branch_bound_fill(
                result,
                approxes,
                rounds,
                bound,
                round,
                new_elp,
                pin,
                pout | mask,
                n + 1
            );
        }
        return bound;
    }

    assert(n == Sboxes);

    // apply permutation

    pin = permute(pout);

    // check if at end

    if (round == rounds) {
        assert(elp < 1);
        assert(elp > 0);
        assert(elp > bound);
        result = pout;
        return elp;
    }

    // progress to next round

    return branch_bound_fill(
        result,
        approxes,
        rounds,
        bound,
        round + 1,
        elp,
        pin,
        0,
        0
    );
}

std::pair<uint64_t, double> branch_bound_search(
    std::vector<approx_t> (&approxes) [CIPHER_SBOX_VALUES], // elp approx
    size_t rounds, // number of rounds to search
    uint64_t pin   // input parity
) {
    double elp = 1;
    uint64_t mask = pin; // some value

    for (size_t rnd = 0; rnd <= rounds; rnd++) {

        // extend best trail to n rounds

        #ifndef NDEBUG
        printf("%3zu : extending mask 0x%016lx (2^%f) -> ", rnd, mask, log2(elp));
        #endif

        elp = branch_bound_fill(
            mask,     // new best trail end mask
            approxes, // approximation table
            rnd+1,    // one additional round
            0,        // bound = none
            rnd,      // start at offset
            elp,      // E(LP) of trail is bound
            mask,     // last round mask
            0,
            0
        );

        #ifndef NDEBUG
        printf("0x%016lx (2^%f)\n", mask, log2(elp));
        #endif

        // bounded search for best n-round trail

        #ifndef NDEBUG
        printf("%3zu : improving mask 0x%016lx (2^%f) -> ", rnd, mask, log2(elp));
        #endif

        elp = branch_bound_fill(
            mask,
            approxes,
            rnd,
            elp,
            0,
            1,
            pin,
            0,
            0
        );

        #ifndef NDEBUG
        printf("0x%016lx (2^%f)\n", mask, log2(elp));
        #endif
    }

    return std::pair<uint64_t, double>(mask, elp);
}
#endif
