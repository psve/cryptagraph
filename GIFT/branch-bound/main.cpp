#include "cipher.cpp"
#include "search.cpp"

#include <iostream>

int main(int argc, char *argv[]) {
    std::vector<approx_t> forward_approx  [CIPHER_SBOX_VALUES];
    std::vector<approx_t> backward_approx [CIPHER_SBOX_VALUES];

    approximate_sbox (
        forward_approx,
        backward_approx
    );

    make_approximations_elp(forward_approx);
    make_approximations_elp(backward_approx);

    branch_bound_search<6>(forward_approx);

    return 0;
}
