#include <stdlib.h>
#include <string.h>

/* Duplicate the first n bytes of src into a freshly allocated, NUL-terminated
   buffer. FIXED: n is widened to size_t before adding 1, so the length
   calculation cannot wrap and the allocation always has room for n bytes plus
   the terminator. */
char *dup_n(const char *src, unsigned short n) {
    size_t total = (size_t)n + 1;
    char *buf = malloc(total);
    if (buf == NULL) {
        return NULL;
    }
    memcpy(buf, src, n);
    buf[n] = '\0';
    return buf;
}
