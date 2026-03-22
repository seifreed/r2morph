
#include <iostream>
#include <stdexcept>

int thrower(int x) {
    if (x < 0) throw std::runtime_error("negative");
    return x * 2;
}

int catcher(int x) {
    try {
        return thrower(x);
    } catch (const std::runtime_error& e) {
        return -1;
    } catch (...) {
        return -2;
    }
}

int main(int argc, char **argv) {
    int val = 0;
    if (argc > 1) val = atoi(argv[1]);
    return catcher(val);
}
