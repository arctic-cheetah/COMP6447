#include <stdio.h>
#include <strings.h>

int main()
{
    execve("/bin/sh", NULL, NULL);
}