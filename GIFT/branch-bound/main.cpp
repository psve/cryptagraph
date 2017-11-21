#include "cipher.cpp"
#include "search.cpp"

#include <iostream>

int main(int argc, char *argv[]) {

    static const size_t Rounds = 12;

    std::vector<approx_t> forward_approx  [CIPHER_SBOX_VALUES];
    std::vector<approx_t> backward_approx [CIPHER_SBOX_VALUES];

    approximate_sbox (
        forward_approx,
        backward_approx
    );

    make_approximations_elp(forward_approx);
    make_approximations_elp(backward_approx);

    double bounds[Rounds + 1];
    uint64_t trail[Rounds + 1] = {0};

    branch_bound_search<Rounds>(forward_approx, bounds, trail);

    printf("2^%f\n", log2(bounds[Rounds]));
    for (size_t r = 0; r <= Rounds; r++) {
        printf("%016lx\n", trail[r]);
    }

    return 0;
}
