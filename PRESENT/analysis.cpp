#ifndef __ATTACK_ANALYSIS__
#define __ATTACK_ANALYSIS__

#include "present.cpp"
#include "helpers.cpp"

#include <vector>
#include <algorithm>

#include <math.h>
#include <assert.h>

struct approx_t {
    uint64_t input;
    uint64_t output;
    size_t weight;
    double corr;
};

size_t nibbles(uint64_t a) {
    size_t n = 0;
    for (size_t i = 0; i < sizeof(a) * 2; i++) {
        if (a & 0xf)
            n++;
        a >>= 4;
    }
    return n;
}

/* make all correlations non-negative
 * (used for calculating the linear potential)
 */
void make_approximations_elp(
    std::vector<approx_t> (&approximations) [SBOX_VALUES]
) {
    for (size_t n = 0; n < SBOX_VALUES; n++) {
        for (auto &approx : approximations[n]) {
            approx.corr = approx.corr * approx.corr;
        }
    }
}

void approximate_sbox (
    std::vector<approx_t> (&forward_approx) [SBOX_VALUES],
    std::vector<approx_t> (&backward_approx) [SBOX_VALUES]
) {
    #ifndef NDEBUG
    printf("Enumerating linear approximations of SBOX\n");
    #endif
    for (size_t parin = 0; parin < SBOX_VALUES; parin++) {
        for (size_t parout = 0; parout < SBOX_VALUES; parout++) {
            double hits = 0.0;
            for (size_t input = 0; input < SBOX_VALUES; input++) {
                auto p0 = parity(parin & input);
                auto p1 = parity(parout & SBOX[input]);

                assert((p0 & 1) == p0);
                assert((p1 & 1) == p1);

                if (p0 == p1)
                    hits += 1.0;
            }

            {
                approx_t approx;
                approx.input = parin;
                approx.output = parout;
                approx.corr = 2.0 * (hits / SBOX_VALUES) - 1.0;
                approx.weight = weight(approx.output);
                forward_approx[approx.input].push_back(approx);
            }

            {
                approx_t approx;
                approx.input = parout;
                approx.output = parin;
                approx.corr = 2.0 * (hits / SBOX_VALUES) - 1.0;
                approx.weight = weight(approx.output);
                backward_approx[approx.input].push_back(approx);
            }

            #ifndef NDEBUG
            printf("%2zu, ", size_t(hits));
            #endif
        }
        #ifndef NDEBUG
        printf("\n");
        #endif
    }

    for (size_t n = 0; n < SBOX_VALUES; n++) {
        auto &vec_f = forward_approx[n];
        auto &vec_b = backward_approx[n];

        // sort
        auto vsort = [](std::vector<approx_t>& v) {
            std::sort(v.begin(), v.end(), [](approx_t a, approx_t b) {
                return fabs(b.corr) < fabs(a.corr);
            });
        };
        vsort(vec_f);
        vsort(vec_b);

        // remove
        auto vremove = [](std::vector<approx_t>& v) {
            for (size_t n = 0; n < v.size(); n++) {
                auto &elem = v[n];
                if (fabs(elem.corr) < TINY) {
                    v.erase(v.begin() + n, v.end());
                    break;
                }
            }
        };
        vremove(vec_f);
        vremove(vec_b);
    }
}

void approximate_sbox_forward (
    std::vector<approx_t> (&forward_approx) [SBOX_VALUES]
) {
    std::vector<approx_t> backward_approx[SBOX_VALUES];
    approximate_sbox (
        forward_approx,
        backward_approx
    );
}

void approximate_sbox_backward (
    std::vector<approx_t> (&backward_approx) [SBOX_VALUES]
) {
    std::vector<approx_t> forward_approx[SBOX_VALUES];
    approximate_sbox (
        forward_approx,
        backward_approx
    );
}

#endif
