#include <stdio.h>

int main(int argc, int **argv)
{
    // This is probably wrong
    char buff[0x20];
    int varc;

    scanf("%d", &varc);

    if (varc != 0x539)
    {
        puts("Something here");
    }
    else
    {
        puts("Your so leet");
    }
}
