#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

#include "../mymalloc.h"
#include "testing.h"

int main() {
  set_mem_limit((16ull << 20) << 3 /* bytes */);

  int *ptr = my_malloc(sizeof(int *));
  CHECK_NULL(ptr);

  *ptr = 10;

  ptr = my_malloc(sizeof(int *));
  CHECK_NULL(ptr);
  *ptr = 20;

  my_free(ptr);

  return EXIT_SUCCESS;
}
