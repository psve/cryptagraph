// avoid explicit recursion using an array of coroutines

#include "analysis.cpp"

class SearchRoutine {

    size_t n = 0;
    std::vector<approx_t> approx[CIPHER_SBOX_VALUES];

    public:
        SearchRoutine(std::vector<approx_t> (&approx) [CIPHER_SBOX_VALUES]) {

            // load local

            for (size_t n = 0; n < CIPHER_SBOX_VALUES; n++) {
                this->approx[n] = approx[n];
            }
        }

        void reset(std::pair<uint64_t, double> state) {

        }

        // reentrant

        std::pair<uint64_t, double> call() {
            return
        }
};
