#include <stdlib.h>
// Stack frame is 32 bytes
//
int main()
{
    int i = 0;
    while (i < 9)
    {
        // print the number if even
        if (i & 1)
        {
            print("%d", i);
        }
        i++;
    }
    return 0;
}