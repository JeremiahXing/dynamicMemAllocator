#include "testing.h"

int sizes[] = {123, 456, 1, 8, 8, 8, 56, 8, 12, 67, 32497, 123, 456, 8, 8, 8, 6, 6, 6, 12, 12};
void *pointers[21];

int main()
{
  for (int i = 1; i <= 21; i++)
  {
    for (int j = 0; j < i; j++)
      pointers[j] = mallocing(sizes[j]);
    if (i % 2 == 0)
    {

      for (int j = i - 1; j >= 0; j--)
        freeing(pointers[j]);
    }
    else
    {
      for (int j = 0; j < i; j++)
        freeing(pointers[j]);
    }
  }
  return 0;
}
