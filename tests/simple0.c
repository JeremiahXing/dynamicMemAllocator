#include "testing.h"

int main()
{
    // simple test that does nothing requiring malloc()
    int i = 2;
    int j = 3;
    int k = i + j;
    return i + j + k - i - j - k;
}
