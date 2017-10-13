#include "iterate.cpp"

#include <math.h>
#include <iomanip>

#define ARG_HW (1)

void run(
    std::vector<approx_t> (&approximations) [SBOX_VALUES],
    uint64_t alpha,
    size_t hw
) {

    std::unordered_map<uint64_t, double> map1;
    std::unordered_map<uint64_t, double> map2;

    auto &pool_cur = map1;
    auto &pool_new = map2;

    pool_cur[alpha] = 1.0;

    printf("%016lx\n", alpha);

    for (size_t round = 0; round < 22; round++) {
        if (pool_cur.size() == 0)
            break;

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

        // join pool

        double sq_corr = 0;
        for (auto elem : pool_cur) {
            sq_corr += elem.second;
        }
        std::cout << round << " : " << pool_cur.size() << " : " << std::setprecision(15) << sq_corr << " : 2^" << log2(sq_corr) << std::endl;
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    size_t hw;
    size_t box;
    if (argc != 3) {
        printf("usage:\n");
        printf("%s hw index\n", argv[0]);
        return -1;
    }

    sscanf(argv[ARG_HW], "%zu", &hw);
    sscanf(argv[ARG_HW+1], "%zu", &box);

    std::vector<approx_t> approximations [SBOX_VALUES];
    approximate_sbox_forward(approximations);
    make_approximations_elp(approximations);

    for (uint64_t input = 1; input < SBOX_VALUES; input++) {
        uint64_t alpha = input << (box * SIZE_SBOX);
        run(approximations, alpha, hw);
    }
}
