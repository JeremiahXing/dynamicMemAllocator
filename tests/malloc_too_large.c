#include "testing.h"

int main()
{
    void *ptr = my_malloc(kMaxAllocationSize + 1);
    if (ptr != NULL)
        printf("Expected an error for an allocation larger than the maximum allocable amount\n");
    assert(ptr == NULL);
    void *ptr2 = mallocing(8);
    freeing(ptr2);
}
