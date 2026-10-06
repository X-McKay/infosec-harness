#include <stdlib.h>
#include <string.h>

/* Duplicate the first n bytes of src into a freshly allocated, NUL-terminated
   buffer. */
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
