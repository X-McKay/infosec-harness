#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *dup_n(const char *src, unsigned short n);

int main(void) {
    /* Small, in-range length works. */
    char *small = dup_n("hello", 5);
    printf("small: %s\n", small ? small : "(null)");
    free(small);

    /* Bounded boundary input: 65535 bytes (64 KiB). On the vulnerable build the
       n + 1 length wraps to 0, so malloc is tiny and the 65535-byte memcpy
       overflows it; a memory-safety detector fires. The fixed build allocates
       65536 bytes and copies safely. */
    unsigned short n = 65535;
    char *src = malloc(n);
    memset(src, 'A', n);
    char *big = dup_n(src, n);
    printf("big len: %zu\n", big ? strlen(big) : (size_t)0);
    free(big);
    free(src);
    return 0;
}
