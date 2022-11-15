#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

#include "testing.h"
#include "../mymalloc.h"

int main()
{
    volatile int *random_ptr = malloc(sizeof(int));
    *random_ptr = 230;
    my_free(random_ptr);
    return EXIT_SUCCESS;
}
