#include "gift.cpp"
#include "analysis.cpp"

#include <assert.h>
#include <unordered_map>
#include <iostream>

template <typename value_t>
void fill(
    std::unordered_map<uint64_t, value_t>& pool_new,
    std::vector<approx_t> (&approxes) [SBOX_VALUES],
    value_t value,
    uint64_t pin,
    uint64_t pout, // temp, initally 0
    size_t max_weight,
    size_t pat_weight,
    size_t n
) {
    static const size_t Sboxes = SIZE / 4;

    for (; n < Sboxes; n++) {
        // fetch input parity
        auto val_in = (pin >> (n * 4)) & 0xf;
        if (val_in == 0)
            continue;
        if (pat_weight == max_weight)
            return;

        // pick approximations
        for (auto const &approx: approxes[val_in]) {
            assert(approx.input == val_in);
            auto mask = approx.output << (n * 4);
            auto w = pat_weight + 1; // approx.weight;
            if (w > max_weight)
                continue;
            fill(
                pool_new,
                approxes,
                value * approx.corr,
                pin,
                pout | mask,
                max_weight,
                w,
                n + 1
            );
        }
        return;
    }
    assert(weight(pout) <= max_weight);
    pout = permute(pout);
    pool_new[pout] += value;
}
