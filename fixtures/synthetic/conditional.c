#include <stdio.h>

int max(int a, int b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

int main() {
    int a = 42;
    int b = 17;
    int result = max(a, b);
    printf("Max: %d\n", result);
    return 0;
}
