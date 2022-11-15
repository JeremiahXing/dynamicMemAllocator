#include "../mymalloc.h"
#include "testing.h"

int main()
{
    void *ptr = my_malloc(0);
    void *ptr2 = mallocing(8);
    freeing(ptr2);
    if (ptr != NULL)
        printf("Expected NULL for an allocation of 0 bytes\n");
    assert(ptr == NULL);
}
