/* stack.c */

/* This program has a buffer overflow vulnerability. */
/* Our task is to exploit this vulnerability */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int bof(char *str)
{
    char buffer[40];

    /* The following statement has a buffer overflow problem */ 
    strcpy(buffer, str);

    return 1;
}

int main(int argc, char **argv)
{
    char str[400];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    if (badfile == NULL) {
        printf("Cannot open badfile!\n");
        return -1;
    }

    fread(str, sizeof(char), 400, badfile);
    bof(str);

    printf("Returned properly!\n");
    return 1;
}
