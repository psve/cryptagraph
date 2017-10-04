#include <mpi.h>
#include <assert.h>

#include "types.hpp"
#include "mask-search.cpp"

/* Processing:
 *
 * For all rounds:
 *    - Scatter mask set to nodes
 *    - Gather in root
 *    - Merge heaps obtaining new mask set
 */

#define HPC_ROOT (0)
#define HPC_CHILDREN (2)

#define MASK_SET_LIMIT (1 << 12)

template <size_t Limit>
int flatten(elemT* dst, MaskCollector<Limit> &collector) {
    int size = 0;
    while (!collector.empty() && size < Limit) {
        dst[size] = collector.pop();
        size++;
    }
    assert(collector.size() == 0);
    return size;
}

int main(int argc, char* argv[]) {

    const size_t Limit  = 1 << 22;
    const size_t Rounds = 12;

    #ifndef NDEBUG
    std::cout << "warning: debug build" << std::endl;
    #endif

    // parse arguments

    if (argc < 2)
        return -1;

    uint64_t alpha;
    sscanf(argv[ARG_ALPHA], "%lx", &alpha);

    // initialize MPI

    int world_rank;
    int world_size;

    MPI_Init(NULL, NULL);
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    // find children

    int children = 0;
    for (int n = 1; n <= HPC_CHILDREN; n++) {
        auto child = world_rank * HPC_CHILDREN + n;
        if (child < world_size)
            children++;
    }

    #ifndef NDEBUG
    std::cout << "node" << world_rank << ": has " << children << " children" << std::endl;
    #endif

    // collect S-Box approximations

    std::vector<approx_t> fapprox [SBOX_VALUES];
    std::vector<approx_t> bapprox [SBOX_VALUES];
    approximate_sbox(fapprox, bapprox);
    make_approximations_elp(fapprox);
    make_approximations_elp(bapprox);

    // prepare masks (first round on root)

    MaskMap masks;
    MaskCollector<Limit> collector;

    size_t flat_size = 0;
    auto   flat_buff = (elemT*) calloc(Limit, sizeof(elemT));

    if (world_rank == HPC_ROOT) {
        #ifndef NDEBUG
        std::cout << "node" << world_rank << ": computing first round" << std::endl;
        #endif

        auto inital = elemT(alpha, 1);
        masks.insert(inital);
        collect_round<Forwards, Limit>(
            masks,
            collector,
            &inital,
            1,
            fapprox,
            bapprox
        );

        flat_size = flatten<Limit>(flat_buff, collector);
    }


    for (size_t round_num = 1; round_num < Rounds; round_num++){

        assert(collector.empty());


        if (world_rank == HPC_ROOT) {

            // apply permutation if root

            double total_elp = 0;
            for (int n = 0; n < flat_size; n++) {
                flat_buff[n].first = permute(flat_buff[n].first);
                total_elp += flat_buff[n].second;
            }
            std::cout << "node" << world_rank << ": |S| = " << flat_size << ", Round = " << round_num << ", Set-ELP = " << total_elp << std::endl;

            // save to disk

            {
                char name[128];
                sprintf(name, "%x-r%zu.masks", alpha, round_num);
                FILE *f = fopen(name, "w");
                if (f == NULL) {
                    std::cout << "failed to open file: " << name << std::endl;
                    return -1;
                }
                for (int n = 0; n < flat_size; n++) {
                    auto ret = fwrite(
                        &flat_buff[n].first,
                        sizeof(uint64_t),
                        1,
                        f
                    );
                    if (ret != 1) {
                        std::cout << "failed to write all elements: " << std::endl;
                        return -1;
                    }
                }
                fclose(f);
            }
        }

        // syncronize all nodes

        MPI_Barrier(MPI_COMM_WORLD);

        // broadcast (masks)

        MPI_Bcast(
            &flat_size,
            sizeof(flat_size),
            MPI_BYTE,
            HPC_ROOT,
            MPI_COMM_WORLD
        );

        #ifndef NDEBUG
        std::cout << "node" << world_rank << ": receiving " << flat_size << " masks (and ELPs)" << std::endl;
        #endif

        if (flat_size > Limit)
            return -1;

        MPI_Bcast(
            flat_buff,
            flat_size * sizeof(elemT),
            MPI_BYTE,
            HPC_ROOT,
            MPI_COMM_WORLD
        );

        #ifndef NDEBUG
        std::cout << "node" << world_rank << ": receieved mask-set" << std::endl;
        #endif

        // insert into hash map

        masks.clear();
        for (size_t n = 0; n < flat_size; n++) {
            masks.insert(flat_buff[n]);
        }
        assert(masks.size() == flat_size);
        assert(masks.size() <= Limit);

        // scatter work (based on rank)

        auto work_slice = flat_size / world_size;
        auto work_offset = work_slice * world_rank;
        auto work_elements = flat_size / world_size;

        if (world_rank == world_size - 1) {
            work_elements += flat_size % world_size;
        }

        assert(work_elements + work_offset <= flat_size);

        // do work

        #ifndef NDEBUG
        std::cout << "node" << world_rank << ": WorkElements = " << work_elements << ", WorkOffset = " << work_offset << std::endl;
        std::cout << "node" << world_rank << ": begin search for round " << round_num << std::endl;
        #endif

        collect_round<Forwards, Limit>(
            masks,
            collector,
            flat_buff + work_offset,
            work_elements,
            fapprox,
            bapprox
        );

        #ifndef NDEBUG
        std::cout << "node" << world_rank << ": work complete, results = " << collector.size() << std::endl;
        #endif

        // gather & merge heaps from children

        {
            for (int c = 0; c < children; c++) {

                // fetch flat array

                MPI_Status status;
                auto err = MPI_Recv(
                    flat_buff,
                    Limit * sizeof(elemT),
                    MPI_BYTE,
                    MPI_ANY_SOURCE,
                    0,
                    MPI_COMM_WORLD,
                    &status
                );
                if (err) return err;

                // add to collector

                {
                    int cnt;
                    MPI_Get_count(&status, MPI_INT, &cnt);
                    assert(cnt > 0);
                    assert(cnt <= Limit);
                    for (int n = 0; n < cnt; n++)
                        collector.add(flat_buff[n]);
                }
            }
        }

        // flatten collector to array

        flat_size = flatten<Limit>(flat_buff, collector);

        // send to parent (if any)

        if (world_rank != HPC_ROOT) {
            auto parent = world_rank / HPC_CHILDREN;
            auto err = MPI_Send(
                flat_buff,
                flat_size * sizeof(elemT),
                MPI_BYTE,
                parent,
                0,
                MPI_COMM_WORLD
            );
            if (err) return err;
        }
    }

    MPI_Finalize();
}
