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
    std::vector<approx_t> (&approxes)  [CIPHER_SBOX_VALUES] [Sboxes],
    double   (&bounds)[Rounds + 1], // upper bounds
    uint64_t (&trace)[Rounds + 1],  // resulting trail (trace of execution)
    uint64_t (&trail)[Rounds + 1],  // resulting trail (trace of execution)
    double   elp,                   // elp for trail
    uint64_t pin,                   // input parity
    uint64_t pout,                  // output paritu, initally 0
    size_t   rounds,                // rounds of current search
    size_t   weight,                // sboxes activated
    size_t   r,                     // current round index
    size_t   box                    // sbox index
) {
    assert(box <= Sboxes);
    assert(r <= Rounds);
    assert(r <= rounds);

    static_assert(CIPHER_SBOX_SIZE == 4, "currently assumes 4-bit sbox");

    for (; box < Sboxes; box++) {

        // fetch input parity

        auto val_in = (pin >> (box * CIPHER_SBOX_SIZE)) & 0xf; // 4-bits
        if (val_in == 0)
            continue;

        if (weight >= Weight)
            return;

        // pick approximations

        for (auto const &approx: approxes[box][val_in]) {

            assert(approx.input == val_in);
            assert(rounds - (r + 1) >= 0);

            // check bound

            auto new_elp = elp * approx.corr;

            if (new_elp * bounds[rounds - (r + 1)] <= bounds[rounds])
                continue;

            // fill sbox approximation

            branch_bound_fill<Rounds, Sboxes, Weight>(
                approxes,
                bounds,
                trace,
                trail,
                new_elp,
                pin,
                pout | approx.output,
                rounds,
                weight + 1,
                r,
                box + 1
            );
        }
        return;
    }

    assert(box == Sboxes);

    // check if at end

    assert(r + 1 <= Rounds);

    trace[r + 1] = pout;

    if (r + 1 == rounds) {
        if(elp > bounds[rounds]) {
            bounds[rounds] = elp;
            for (size_t i = 0; i <= rounds; i++)
                trail[i] = trace[i];
        }
        return;
    }

    // progress to next round

    branch_bound_fill<Rounds, Sboxes, Weight>(
        approxes,
        bounds,
        trace,
        trail,
        elp,
        pout,
        0,
        rounds,
        0,
        r + 1,
        0
    );
}

template <size_t Rounds, size_t Sboxes, size_t Weight>
void branch_bound_start(
    std::vector<approx_t> (&approxes) [CIPHER_SBOX_VALUES] [Sboxes],
    double   (&bounds)[Rounds + 1],
    uint64_t (&trail)[Rounds + 1],
    uint64_t pin,
    size_t   rounds,
    size_t   index,
    size_t   remain
) {

    if (remain > 0 && index < Sboxes) {

        size_t c = index * 4;
        for (uint64_t v = 0; v < 16; v++) {
            branch_bound_start<Rounds, Sboxes, Weight>(
                approxes,
                bounds,
                trail,
                pin | (v << c),
                rounds,
                index + 1,
                v == 0 ? remain : remain - 1
            );
        }

    } else if (pin != 0) {

        // printf("%zu %016lx\n", rounds, pin);

        uint64_t trace[Rounds + 1];

        trace[0] = pin;

        branch_bound_fill<Rounds, Sboxes, Weight>(
            approxes,
            bounds,
            trace,
            trail,
            1,
            pin,
            0,
            rounds,
            0,
            0,
            0
        );

        // std::cout << "2^" << log2(bounds[rounds]) << std::endl;

    }
}

template <size_t Rounds>
std::pair<uint64_t, double> branch_bound_search(
    std::vector<approx_t> (&approxes) [CIPHER_SBOX_VALUES] [Sboxes],
    double   (&bounds)[Rounds + 1],
    uint64_t (&trail)[Rounds + 1]
) {

    for (size_t i = 0; i <= Rounds; i++)
        bounds[i] = 0;
    bounds[0] = 1;

    static const size_t Weight = 4;
    static const size_t Sboxes = CIPHER_SIZE / CIPHER_SBOX_SIZE;

    for (size_t rounds = 1; rounds <= Rounds; rounds++) {
        printf("round: %zu\n", rounds);
        bounds[rounds] = bounds[rounds - 1] * 0.00390625; // 2^-8
        branch_bound_start<Rounds, Sboxes, Weight>(
            approxes,
            bounds,
            trail,
            0,
            rounds,
            0,
            Weight
        );
    }
}
#endif
