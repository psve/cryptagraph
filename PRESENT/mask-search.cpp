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

#define ARG_ALPHA (1)

enum Direction { Forwards, Backwards };

typedef std::unordered_map<uint64_t, double> MaskMap;
typedef std::pair<uint64_t, double> elemT;

bool comp = [](elemT a, elemT b ) { return a.second < b.second; };

struct MaskCollector {
    class CompareMask {
        public:
            bool operator() (elemT &a, elemT &b) {
                return a.second > b.second;
            }
    };

    // content

    size_t size;
    std::mutex mutex_;
    std::unordered_set<uint64_t> members;                                // members of heap
    std::priority_queue<elemT, std::vector<elemT>, CompareMask> fitness; // fitness min-heap
};

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


void fill(
    MaskMap const &masks,                           // masks from last round
    MaskCollector &collect,                         // collector of new mask set
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

    // compare with worst mask in collector

    if (elp < TINY)
        return;

    collect.mutex_.lock();

    if (collect.fitness.size() < collect.size) {
        collect.members.insert(pout);
        collect.fitness.push(elemT(pout, elp));
        collect.mutex_.unlock();
        return;
    }

    auto worst = collect.fitness.top();
    if (worst.second >= elp) {
        collect.mutex_.unlock();
        return;
    }

    // remove worst

    collect.fitness.pop();
    collect.members.erase(worst.first);

    // insert new element

    collect.fitness.push(elemT(pout, elp));
    collect.members.insert(pout);

    // release mutex

    collect.mutex_.unlock();
}

template <Direction Dir, size_t Limit>
void collect_round(
    MaskMap const &masks,
    MaskCollector &collect,
    std::vector<approx_t> (&fapprox) [SBOX_VALUES],
    std::vector<approx_t> (&bapprox) [SBOX_VALUES]
) {
    size_t n = 0;

    #pragma omp parallel
    #pragma omp single
    {
        for (auto m : masks) {
            n++;
            if (n && n % 10000 == 0)
                printf("dispatched %7zu / %7zu masks\n", n, masks.size());
            #pragma omp task firstprivate(m)
            {
                fill (
                    masks,
                    collect,
                    fapprox,
                    bapprox,
                    m.first,
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

template <size_t Rounds, size_t Limit, Direction Dir>
void collect_sets(
    MaskMap (&masks) [Rounds],
    std::vector<approx_t> (&fapprox) [SBOX_VALUES],
    std::vector<approx_t> (&bapprox) [SBOX_VALUES]
) {
    struct MaskCollector collector;

    collector.size = 1000000;

    for (size_t r = 1; r < Rounds; r++) {
        std::cout << std::endl;
        std::cout << "round: " << r << std::endl;
        collector.members.clear();

        // collect masks

        assert(collector.members.empty());
        assert(collector.fitness.empty());

        collect_round<Dir, Limit>(
            masks[r-1],
            collector,
            fapprox,
            bapprox
        );

        // empty collector and apply permutation

        double total_elp = 0;
        while (!collector.fitness.empty()) {
            auto elem = collector.fitness.top();
            total_elp += elem.second;
            elem.first = permute(elem.first);
            masks[r].insert(elem);
            collector.fitness.pop();
        }
        std::cout << "total ELP: 2^" << log2(total_elp) << std::endl;
        std::cout << "number of masks: " << std::dec << masks[r].size() << std::endl;
    }
}

int main(int argc, char* argv[]) {

    const size_t Limit  = 1 << 20;
    const size_t Rounds = 12;

#ifndef NDEBUG
    std::cout << "warning: debug build" << std::endl;
#endif

    // parse arguments

    if (argc < 2)
        return -1;

    uint64_t alpha;
    sscanf(argv[ARG_ALPHA], "%lx", &alpha);

    // collect S-Box approximations

    std::vector<approx_t> fapprox [SBOX_VALUES];
    std::vector<approx_t> bapprox [SBOX_VALUES];
    approximate_sbox(fapprox, bapprox);
    make_approximations_elp(fapprox);
    make_approximations_elp(bapprox);

    // induce

    MaskMap masks[Rounds];
    masks[0][alpha] = 1;
    collect_sets<Rounds, Limit, Forwards>(
        masks,
        fapprox,
        bapprox
    );
}
