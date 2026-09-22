// The same source is compiled natively on x86-64 and AArch64.
__attribute__((noinline, used))
int fcg_leaf(int value) {
    return value + 1;
}

__attribute__((noinline, used))
int fcg_left(int value) {
    return fcg_leaf(value) + 2;
}

__attribute__((noinline, used))
int fcg_right(int value) {
    return value * 3;
}

int main(void) {
    volatile int value = 1;
    return fcg_left(value) + fcg_right(value) - 7;
}
