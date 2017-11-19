#ifndef __ATTACK_BRANCH_BOUND__
#define __ATTACK_BRANCH_BOUND__

#include "cipher.cpp"
#include "analysis.cpp"

#include <utility>
#include <iostream>

/* Maintains upper bounds for the remaining rounds
 *
 * bounds[rounds + 1];
 *
 * bounds[0] = 1; // best 0 round trail
 * bounds[1]    ; // best 1 round trail
 * ...
 *
 * when considering n-round trail T, discard if ELP(T) * bounds[n+1] <= bound[n].
 * // uint64_t (&masks)[Rounds],  // recursion tail
 */
template<size_t Rounds, size_t Sboxes, size_t Weight>
void branch_bound_fill(
    std::vector<approx_t> (&approxes) [CIPHER_SBOX_VALUES],
    double   (&bounds)[Rounds + 1], // upper bounds
    double   elp,                   // elp for trail
    uint64_t pin,                   // input parity
    uint64_t pout,                  // output paritu, initally 0
    size_t   rounds,                // rounds of current search
    size_t   weight,                // sboxes activated
    size_t   r,                     // current round index
    size_t   n                      // sbox index
) {
    assert(n <= Sboxes);
    assert(r <= Rounds);
    assert(r <= rounds);

    static_assert(CIPHER_SBOX_SIZE == 4, "currently assumes 4-bit sbox");

    for (; n < Sboxes; n++) {

        // fetch input parity

        auto val_in = (pin >> (n * CIPHER_SBOX_SIZE)) & 0xf; // 4-bits
        if (val_in == 0)
            continue;

        if (weight >= Weight)
            return;

        // pick approximations

        for (auto const &approx: approxes[val_in]) {

            assert(approx.input == val_in);
            assert(rounds - (r + 1) >= 0);

            // check bound

            auto new_elp = elp * approx.corr;

            if (new_elp * bounds[rounds - (r + 1)] <= bounds[rounds])
                continue;

            // fill sbox approximation

            auto mask = approx.output << (n * CIPHER_SBOX_SIZE);

            branch_bound_fill<Rounds, Sboxes, Weight>(
                approxes,
                bounds,
                new_elp,
                pin,
                pout | mask,
                rounds,
                weight + 1,
                r,
                n + 1
            );
        }
        return;
    }

    assert(n == Sboxes);

    // apply permutation

    pin = permute(pout);

    // check if at end

    if (r + 1 == rounds) {
        if(elp > bounds[rounds])
            bounds[rounds] = elp;
        return;
    }

    // progress to next round

    branch_bound_fill<Rounds, Sboxes, Weight>(
        approxes,
        bounds,
        elp,
        pin,
        0,
        rounds,
        0,
        r + 1,
        0
    );
}

template <size_t Rounds, size_t Sboxes, size_t Weight>
void branch_bound_start(
    std::vector<approx_t> (&approxes) [CIPHER_SBOX_VALUES],
    double   (&bounds)[Rounds + 1],
    uint64_t pin,
    size_t rounds,
    size_t index,
    size_t remain
) {

    if (remain > 0 && index < Sboxes) {

        size_t c = index * 4;
        for (uint64_t v = 0; v < 16; v++) {
            branch_bound_start<Rounds, Sboxes, Weight>(
                approxes,
                bounds,
                pin | (v << c),
                rounds,
                index + 1,
                v == 0 ? remain : remain - 1
            );
        }

    } else if (pin != 0) {

        printf("%zu %016lx\n", rounds, pin);

        branch_bound_fill<Rounds, Sboxes, Weight>(
            approxes,
            bounds,
            1,
            pin,
            0,
            rounds,
            0,
            0,
            0
        );

        std::cout << "2^" << log2(bounds[rounds]) << std::endl;

    }
}

template <size_t Rounds>
std::pair<uint64_t, double> branch_bound_search(
    std::vector<approx_t> (&approxes) [CIPHER_SBOX_VALUES]
) {
    double bounds[Rounds + 1] = {0};
    bounds[0] = 1;

    static const size_t Weight = 5;
    static const size_t Sboxes = CIPHER_SIZE / CIPHER_SBOX_SIZE;

    for (size_t rounds = 1; rounds <= Rounds; rounds++) {
        bounds[rounds] = bounds[rounds - 1] * 0.00390625; // 2^-8
        branch_bound_start<Rounds, Sboxes, Weight>(
            approxes,
            bounds,
            0,
            rounds,
            0,
            2
        );
    }
}
#endif
