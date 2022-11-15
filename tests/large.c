#include "testing.h"

#define NALLOCS 100
#define NLOOPS 4

int main()
{
    for (int j = 0; j < NLOOPS; j++)
    {
        void *ptrs[NALLOCS];
        mallocing_loop(ptrs, 10000, NALLOCS);

        for (int i = j % 2; i < NALLOCS; i += 2)
        {
            freeing(ptrs[i]);
        }
    }
}
