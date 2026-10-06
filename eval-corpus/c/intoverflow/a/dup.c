#include <stdlib.h>
#include <string.h>

/* Duplicate the first n bytes of src into a freshly allocated, NUL-terminated
   buffer. VULNERABLE: the length calculation n + 1 is done in unsigned short,
   so n == 65535 wraps total to 0 (CWE-190 -> CWE-680). malloc(0) returns a tiny
   region, and the memcpy of n bytes then writes far past it. */
char *dup_n(const char *src, unsigned short n) {
    unsigned short total = n + 1;
    char *buf = malloc(total);
    if (buf == NULL) {
        return NULL;
    }
    memcpy(buf, src, n);
    buf[n] = '\0';
    return buf;
}
