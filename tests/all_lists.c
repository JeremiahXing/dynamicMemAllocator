#include "testing.h"

int main()
{

    for (size_t i = 1; i <= N_LISTS; i++)
    {
        size_t s = 8 * (i + 1);
        void *ptr = mallocing(s);
        // Malloc a gap in the freelist
        mallocing(s + 8);
        freeing(ptr);
    }

    return 0;
}
