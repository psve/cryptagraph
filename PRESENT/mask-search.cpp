#include <queue>
#include <vector>
#include <utility>
#include <iomanip>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include "analysis.cpp"

#define ARG_ALPHA (1)

enum Direction { Forwards, Backwards };

typedef std::unordered_map<uint64_t, double> MaskMap;
typedef std::pair<uint64_t, double> elemT;

auto comp = [](elemT a, elemT b ) { return a.second < b.second; };

struct MaskCollector {
    size_t size;
    std::unordered_set<uint64_t> members;                                   // members of heap
    std::priority_queue<elemT, std::vector<elemT>, decltype(comp)> fitness; // fitness min-heap
};

/* Applies the inverse round function to
 * determine the E(LP) with the existing mask-set
 *
 * WARNINING: NO PERMUTATION APPLIED
 */
double back_propergate(
    std::vector<approx_t> (&approx) [SBOX_VALUES], // sbox^-1 approx
    MaskMap &pre_masks,                            // the mask set before this round
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

    return pre_masks[pout]; // default value: 0
}

void fill(
    MaskMap &masks,                                 // masks from last round
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

    if (collect.members.find(pout) != collect.members.end())
        return;

    // back propergate to find E(LP)

    double elp = back_propergate(
        bapprox,
        masks,
        pout,
        0,
        1,
        0
    );

    if (elp < TINY)
        return;

    if (collect.fitness.size() < collect.size) {
        collect.members.insert(pout);
        collect.fitness.push(elemT(pout, elp));
        return;
    }

    auto worst = collect.fitness.top();
    if (worst.second >= elp)
        return;

    // remove worst

    collect.fitness.pop();
    collect.members.erase(pout);

    // insert new element

    collect.fitness.push(elemT(pout, elp));
    collect.members.insert(pout);
}

template <Direction Dir, size_t Limit>
void collect_round(
    MaskMap &masks,
    MaskCollector &collect,
    std::vector<approx_t> (&fapprox) [SBOX_VALUES],
    std::vector<approx_t> (&bapprox) [SBOX_VALUES]
) {
    std::cout << "size: " << masks.size() << std::endl;
    for (auto m : masks) {
        std::cout << "process: " << std::setfill('0') << std::setw(16) << std::hex << m.first << std::endl;
        fill (
            masks,
            collect,
            fapprox,
            bapprox,
            m.first,
            0, // pout
            8, // max-weight
            0, // pat-weight
            0  // n
        );
    }
}

void reduce_set(
    MaskMap &masks,
    size_t limit
) {
    typedef std::pair<uint64_t, double> elemT;

#ifndef NDEBUG
    std::cout << "reducing mask set: " << std::dec << masks.size();
#endif

    // extract best

    // TODO: test this code

    auto comp = [](elemT a, elemT b ) { return a.second < b.second; };

    std::priority_queue<elemT, std::vector<elemT>, decltype(comp)> chosen(comp);

    for (auto p : masks) {
        if (chosen.size() < limit) {
            chosen.push(p);
            continue;
        }
        if (comp(chosen.top(), p)) {
            chosen.pop();
            chosen.push(p);
        }
    }

    // feed back to mask set

    masks.clear();

    while (!chosen.empty()) {
        masks.insert(chosen.top());
        chosen.pop();
    }

#ifndef NDEBUG
    std::cout << " -> " << std::dec << masks.size() << std::endl;
#endif
}

template <size_t Rounds, size_t Limit, Direction Dir>
void collect_sets(
    MaskMap (&masks) [Rounds],
    std::vector<approx_t> (&fapprox) [SBOX_VALUES],
    std::vector<approx_t> (&bapprox) [SBOX_VALUES]
) {
    struct MaskCollector collector;

    for (size_t r = 1; r < Rounds; r++) {

        // collect masks

        collector.members.clear();
        collect_round<Dir, Limit>(
            masks[r-1],
            collector,
            fapprox,
            bapprox
        );

        // empty collector

        while (!collector.fitness.empty()) {
            auto elem = collector.fitness.top();
            masks[r].insert(elem);
            collector.fitness.pop();
        }
        std::cout << "number of old masks: " << std::dec << masks[r].size() << std::endl;
        std::cout << "number of new masks: " << std::dec << masks[r-1].size() << std::endl;
        getc(stdin);
    }
}

int main(int argc, char* argv[]) {

    const size_t Limit  = 1 << 20;
    const size_t Rounds = 5;

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
