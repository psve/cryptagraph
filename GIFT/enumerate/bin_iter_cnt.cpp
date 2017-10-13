#include "present.cpp"
#include "analysis.cpp"

#include <assert.h>
#include <unordered_map>
#include <iostream>

#include <math.h>

#include <boost/multiprecision/cpp_int.hpp>

using namespace boost::multiprecision;


#define ARG_ALPHA (1)
#define ARG_BETA  (2)
#define ARG_HW    (3)

typedef checked_uint256_t counter;

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
            auto w = pat_weight + approx.weight;
            if (w > max_weight)
                continue;
            fill(
                pool_new,
                approxes,
                value,
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

int main(int argc, char* argv[]) {
    size_t hw;
    uint64_t alpha;
    uint64_t beta;
    if (argc != 4) {
        printf("usage:\n");
        printf("%s alpha beta hw\n", argv[0]);
        return -1;
    }

    sscanf(argv[ARG_ALPHA], "%lx", &alpha);
    sscanf(argv[ARG_BETA], "%lx", &beta);
    sscanf(argv[ARG_HW], "%zu", &hw);

    printf("hw   : %lx\n", hw);
    printf("beta : %lx\n", beta);
    printf("alpha: %lx\n", alpha);

    std::vector<approx_t> approximations [SBOX_VALUES];
    approximate_sbox_forward(approximations);
    make_approximations_elp(approximations);

    std::unordered_map<uint64_t, counter> map1;
    std::unordered_map<uint64_t, counter> map2;

    auto &pool_cur = map1;
    auto &pool_new = map2;

    pool_cur[alpha] = 1;

    for (size_t round = 0; round < 22; round++) {
        printf("%2zu : %zu\n", round, pool_cur.size());

        // fill new pool
        assert(pool_new.size() == 0);
        for (auto const &elem: pool_cur) {
            fill(
                pool_new,
                approximations,
                elem.second,
                elem.first,
                0,
                hw,
                0,
                0
            );
        }

        // swap
        {
            auto temp = pool_cur;
            pool_cur = pool_new;
            pool_new = temp;
            pool_new.clear();
        }
    }

    auto cnt = pool_cur[beta];
    std::cout << "trails: " << cnt << std::endl;
}
