
int helper(int x);

int entry(int x) {
    return helper(x);
}

int helper(int x) {
    if (x <= 0) return 0;
    if (x == 1) return 1;
    return helper(x - 1) + helper(x - 2);
}

int main(int argc, char **argv) {
    int val = 10;
    if (argc > 1) val = atoi(argv[1]);
    return entry(val);
}
