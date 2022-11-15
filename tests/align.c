#include "testing.h"
#include <assert.h>
#include <stdbool.h>

bool is_word_aligned(void* ptr) {
    return (((size_t)ptr) & (sizeof(size_t) - 1)) == 0;
}

int main()
{
    void *ptr = mallocing(1);
    assert(is_word_aligned(ptr));
    void *ptr2 = mallocing(1);
    assert(is_word_aligned(ptr2));
    return 0;
}
