#include <stdio.h>
#include <string.h>

int format_greeting(const char *name, char *out, size_t outcap);

int main(void) {
    char out[64];

    /* In-bounds name must produce a normal greeting. */
    format_greeting("alice", out, sizeof out);
    printf("normal: %s\n", out);

    /* Bounded over-length name: 24 bytes into a 16-byte buffer. */
    char big[25];
    memset(big, 'A', 24);
    big[24] = '\0';
    format_greeting(big, out, sizeof out);
    printf("long: %s\n", out);
    return 0;
}
