#include <stdio.h>
#include <string.h>

/* Build a greeting from an untrusted name into a 16-byte stack buffer. */
int format_greeting(const char *name, char *out, int outcap) {
    char buf[16];
    snprintf(buf, sizeof buf, "%s", name);
    return snprintf(out, outcap, "hi %s", buf);
}
