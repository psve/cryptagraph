#ifndef __ATTACK_BRANCH_BOUND__
#define __ATTACK_BRANCH_BOUND__

#include "cipher.cpp"
#include "analysis.cpp"

#include <utility>
#include <iostream>

double branch_bound_fill(
    uint64_t& result,
    std::vector<approx_t> (&approxes) [CIPHER_SBOX_VALUES], // elp approx
    size_t rounds,     // number of rounds to search
    double bound,      // elp, lower bound
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
            if (new_elp < bound)
                continue;

            // fill sbox approximation

            auto mask = approx.output << (n * CIPHER_SBOX_SIZE);
            bound = fmax(
                bound,
                branch_bound_fill(
                    result,
                    approxes,
                    rounds,
                    bound,
                    round,
                    new_elp,
                    pin,
                    pout | mask,
                    n + 1
                )
            );
        }
        return 0;
    }

    assert(n == Sboxes);

    // check if at end

    if (round == rounds) {
        result = pout;
        return elp;
    }

    std::cout << "end" << std::endl;

    // apply permutation

    pin = permute(pout);

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
    double bound = 0;
    uint64_t result = ~0; // some value
    for (size_t rnd = 1; rnd <= rounds; rnd++) {
        #ifndef NDEBUG
        std::cout << "branching for " << rnd << " rounds, with bound: " << bound << std::endl;
        #endif
        bound = branch_bound_fill(
            result,
            approxes,
            rnd,
            bound,
            0,
            1,
            pin,
            0,
            0
        );
    }
    return std::pair<uint64_t, double>(result, bound);
}
#endif
