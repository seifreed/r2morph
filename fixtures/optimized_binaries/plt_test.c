
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int external_func(int);

int caller(int x) {
    return external_func(x) + external_func(x * 2) + strlen("test");
}

int main(int argc, char **argv) {
    int val = 0;
    if (argc > 1) val = atoi(argv[1]);
    return caller(val);
}
