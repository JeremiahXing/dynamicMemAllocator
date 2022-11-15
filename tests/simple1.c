#include "testing.h"

int main()
{

    int *mem1 = (int *)mallocing(8);
    *mem1 = 10;
    return *mem1 - *mem1;
}
