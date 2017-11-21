#include "iterate.cpp"

#include <math.h>
#include <iomanip>

#define ARG_HW (1)

void init_pool(
    std::unordered_map<uint64_t, double> &map1,
    uint64_t pin,
    size_t index,
    size_t hw
) {

    if (hw == 0 || index >= 16) {
        map1[pin] = 1.0;
        return;
    }

    size_t sht = index * SIZE_SBOX;

    for (uint64_t v = 0; v < SBOX_VALUES; v++) {
        init_pool(
            map1,
            pin | (v << sht),
            index + 1,
            v == 0 ? hw : hw - 1
        );
    }
}

void run(
    std::vector<approx_t> (&approximations) [SBOX_VALUES],
    uint64_t alpha,
    size_t hw
) {

    std::unordered_map<uint64_t, double> map1;
    std::unordered_map<uint64_t, double> map2;

    auto &pool_cur = map1;
    auto &pool_new = map2;

    printf("create initial pool\n");

    init_pool(pool_cur, 0, 0, hw);

    printf("running\n");

    for (size_t round = 0; round < 22; round++) {
        if (pool_cur.size() == 0)
            break;

        // fill new pool
        size_t pcs = 0;

        assert(pool_new.size() == 0);
        for (auto const &elem: pool_cur) {
            if ((++pcs & 0xffff) == 0)
                printf("%zu / %zu\n", pcs, pool_cur.size());
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
            pcs++;
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
