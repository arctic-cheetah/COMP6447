#include <stdio.h>

int main()
{
    char buf[0x14];
    puts("Enter secret");
    fgets(buf, 0x14, stdin);
    if (strcmp(buf, "secret"))
    {
        puts("You lose");
    }
    else
    {
        printf("Congrats you got it %s", &buf);
    }
    return 0;
}