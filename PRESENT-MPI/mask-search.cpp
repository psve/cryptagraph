// stream imports

#include <utility>
#include <iomanip>
#include <iostream>

// data structures

#include <queue>
#include <mutex>
#include <vector>
#include <atomic>
#include <unordered_map>
#include <unordered_set>

// the nice subset of this lang

#include <math.h>
#include <assert.h>

#include "analysis.cpp"
#include "types.hpp"

#define ARG_ALPHA (1)

#ifndef NDEBUG
bool DEBUG_FOUND_BACKPROP;
#endif

/* Applies the inverse round function to
 * determine the E(LP) with the existing mask-set
 *
 * WARNINING: NO PERMUTATION APPLIED
 */
double back_propergate(
    std::vector<approx_t> (&approx) [SBOX_VALUES], // sbox^-1 approx
    MaskMap const &pre_masks,                      // the mask set before this round
    uint64_t pin,                                  // mask after round
    uint64_t pout,                                 // mask before round           (init: 0)
    double corr,                                   // ELP/corr of this sbox layer (init: 1)
    size_t n                                       // sbox index                  (init: 0)
) {
    static const size_t Sboxes = SIZE / 4;

    for (; n < Sboxes; n++) {

        // fetch input parity

        auto val_in = (pin >> (n * 4)) & 0xf;
        if (val_in == 0)
            continue;

        // pick approximations

        double col_corr = 0;
        for (auto const &apx: approx[val_in]) {
            assert(apx.input == val_in);
            auto setter = apx.output << (n * 4);
            col_corr += back_propergate (
                approx,
                pre_masks,
                pin,
                pout | setter,
                corr * apx.corr,
                n + 1
            );
        }
        return col_corr;
    }

    // recursion leaf

    auto pre = pre_masks.find(pout);
    if (pre == pre_masks.end())
        return 0.0;
    #ifndef NDEBUG
    DEBUG_FOUND_BACKPROP = true;
    #endif
    return pre->second * corr;
}

template <size_t Limit>
void fill(
    MaskMap const &masks,                           // masks from last round
    MaskCollector<Limit> &collect,                  // collector of new mask set
    std::vector<approx_t> (&fapprox) [SBOX_VALUES], // forward approximation table
    std::vector<approx_t> (&bapprox) [SBOX_VALUES], // backward approximation table
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

        for (auto const &apx: fapprox[val_in]) {
            assert(apx.input == val_in);
            auto mask = apx.output << (n * 4);
            auto wght = pat_weight + 1;

            if (wght > max_weight)
                continue;

            fill(
                masks,
                collect,
                fapprox,
                bapprox,
                pin,
                pout | mask,
                max_weight,
                wght,
                n + 1
            );
        }
        return;
    }

    // recursion leaf

    collect.mutex_.lock();
    auto found = collect.members.find(pout) != collect.members.end();
    collect.mutex_.unlock();
    if (found)
        return;

    // back propergate to find E(LP)

    #ifndef NDEBUG
    DEBUG_FOUND_BACKPROP = false;
    #endif

    double elp = back_propergate(
        bapprox,
        masks,
        pout,
        0,
        1,
        0
    );

    assert(DEBUG_FOUND_BACKPROP);

    // add to collector

    if (elp < TINY)
        return;

    collect.mutex_.lock();
    collect.add(elemT(pout, elp));
    collect.mutex_.unlock();
}

template <Direction Dir, size_t Limit>
void collect_round(
    MaskMap const &masks,
    MaskCollector<Limit> &collect,
    elemT slice[], int size, // element to process
    std::vector<approx_t> (&fapprox) [SBOX_VALUES],
    std::vector<approx_t> (&bapprox) [SBOX_VALUES]
) {
    #pragma omp parallel
    #pragma omp single
    {
        for (int n = 0; n < size; n++) {
            #pragma omp task firstprivate(n)
            {
                fill (
                    masks,
                    collect,
                    fapprox,
                    bapprox,
                    slice[n].first,
                    0,  // pout
                    4,  // max-weight
                    0,  // pat-weight
                    0   // n
                );
            }
        }
        #pragma omp taskwait
    }
}

