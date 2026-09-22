#include <stdio.h>

// This function is deliberately not called by the original program.
__attribute__((noinline, used))
void entryAdvice(void) {
    puts("advice");
}

int main(void) {
    puts("main");
    return 0;
}
