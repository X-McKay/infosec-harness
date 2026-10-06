#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *dup_n(const char *src, unsigned short n);

int main(void) {
    /* Small, in-range length works. */
    char *small = dup_n("hello", 5);
    printf("small: %s\n", small ? small : "(null)");
    free(small);

    /* Bounded boundary input: 65535 bytes (64 KiB). */
    unsigned short n = 65535;
    char *src = malloc(n);
    memset(src, 'A', n);
    char *big = dup_n(src, n);
    printf("big len: %zu\n", big ? strlen(big) : (size_t)0);
    free(big);
    free(src);
    return 0;
}
