
#include <stdio.h>

int process_switch(int x) {
    switch(x) {
        case 0: return 1;
        case 1: return 2;
        case 2: return 3;
        case 3: return 4;
        case 4: return 5;
        case 5: return 6;
        case 6: return 7;
        case 7: return 8;
        case 8: return 9;
        case 9: return 10;
        default: return -1;
    }
}

int main(int argc, char **argv) {
    int val = 0;
    if (argc > 1) val = atoi(argv[1]);
    return process_switch(val);
}
