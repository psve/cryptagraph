#ifndef __TYPES__
#define __TYPES__

#include <queue>
#include <mutex>
#include <vector>
#include <atomic>
#include <unordered_map>
#include <unordered_set>

enum Direction { Forwards, Backwards };

typedef std::unordered_map<uint64_t, double> MaskMap;
typedef std::pair<uint64_t, double> elemT;

template <size_t Limit>
struct MaskCollector {
    class CompareMask {
        public:
            bool operator() (elemT &a, elemT &b) {
                return a.second > b.second;
            }
    };

    bool empty() {
        return fitness.empty();
    }

    size_t size() {
        assert(fitness.size() == members.size());
        assert(fitness.size() <= Limit);
        return fitness.size();
    }

    void add(elemT elem) {
        // check if already a member

        auto found = members.find(elem.first) != members.end();
        if (found)
            return;

        // compare with worst

        if (fitness.size() >= Limit) {
            auto worst = fitness.top();
            if (worst.second >= elem.second)
                return;

            fitness.pop();
            members.erase(worst.first);
        }

        // insert new element

        fitness.push(elem);
        members.insert(elem.first);
    }

    elemT pop() {
        auto worst = fitness.top();
        fitness.pop();
        members.erase(worst.first);
        return worst;
    }

    // content

    std::mutex mutex_; // used for local syncronization
    std::unordered_set<uint64_t> members;                                // members of heap
    std::priority_queue<elemT, std::vector<elemT>, CompareMask> fitness; // fitness min-heap
};

#endif
