
#include "present.cpp"
#include <stdio.h>

int main() {
    uint64_t input = 0xcafebabe13371337;
    printf("%lx\n", permute(input));
}
