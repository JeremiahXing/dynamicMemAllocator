#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/resource.h>
#include "../mymalloc.h"

#define CHECK_NULL(x)                                                       \
    do {                                                                    \
        if (x == NULL) {                                                    \
            fprintf(stderr, "my_malloc returned NULL. Aborting program\n"); \
            abort();                                                        \
        }                                                                   \
    } while (0)

static void set_mem_limit(size_t bytes)
{
    struct rlimit mem_limit;
    mem_limit.rlim_cur = bytes;
    mem_limit.rlim_max = bytes;

    setrlimit(RLIMIT_AS, &mem_limit);
}

static inline void **mallocing_loop(void **array, size_t size, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        void *v = my_malloc(size);
        CHECK_NULL(v);
        if (array != NULL)
            array[i] = v;
    }
    return array;
}

static inline void *mallocing(size_t size)
{
    void *ptr = my_malloc(size);
    CHECK_NULL(ptr);
    return ptr;
}

static inline void freeing_loop(void **array, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        my_free(array[i]);
    }
}

static inline void freeing(void *ptr)
{
    my_free(ptr);
}
