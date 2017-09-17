#include <queue>
#include <vector>
#include <utility>
#include <iomanip>
#include <iostream>
#include <unordered_map>
#include "analysis.cpp"

#define ARG_ALPHA (1)

enum Direction { Forwards, Backwards };

typedef std::unordered_map<uint64_t, double> MaskMap;

void fill(
    MaskMap &pool_new,
    std::vector<approx_t> (&approx) [SBOX_VALUES],
    double elp,
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

        for (auto const &apx: approx[val_in]) {
            assert(apx.input == val_in);
            auto mask = apx.output << (n * 4);
            auto wght = pat_weight + 1;

            if (wght > max_weight)
                continue;

            fill(
                pool_new,
                approx,
                elp * apx.corr,
                pin,
                pout | mask,
                max_weight,
                wght,
                n + 1
            );
        }
        return;
    }
    pout = permute(pout);
    pool_new[pout] += elp;
}

template <Direction Dir, size_t Limit>
void collect_round(
    MaskMap &o_masks,
    MaskMap &i_masks,
    std::vector<approx_t> (&approx) [SBOX_VALUES]
) {
    std::cout << "size: " << i_masks.size() << std::endl;
    for (auto m : i_masks) {
        std::cout << "process: " << std::setfill('0') << std::setw(16) << std::hex << m.first << std::endl;
        fill(
            o_masks,
            approx,
            m.second,
            m.first,
            0,
            8,
            0,
            0
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
    std::vector<approx_t> (&approx) [SBOX_VALUES]
) {
    for (size_t r = 1; r < Rounds; r++) {
        collect_round<Dir, Limit>(
            masks[r],
            masks[r-1],
            approx
        );
        std::cout << "number of masks: " << std::dec << masks[r].size() << std::endl;
        reduce_set(masks[r], Limit);
        std::cout << "number of masks: " << std::dec << masks[r].size() << std::endl;
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
        fapprox
    );
}
