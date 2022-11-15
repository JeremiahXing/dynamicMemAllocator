#ifndef MYMALLOC_HEADER
#define MYMALLOC_HEADER

#include <stddef.h>

#define USE(...)             \
    do                       \
    {                        \
        (void)(__VA_ARGS__); \
    } while (0)

#ifdef ENABLE_LOG
#define LOG(...) fprintf(stderr, "[malloc] " __VA_ARGS__);
#else
#define LOG(...)
#endif

#define N_LISTS 59

// Word alignment
const size_t kAlignment = sizeof(size_t);
// Minimum allocation size (1 word)
const size_t kMinAllocationSize = kAlignment;
// Maximum allocation size (16 MB)
extern const size_t kMaxAllocationSize;
// Arena size is 4 MB
const size_t ARENA_SIZE = (4ull << 20);

void *my_malloc(size_t size);
void my_free(void *p);

#endif
