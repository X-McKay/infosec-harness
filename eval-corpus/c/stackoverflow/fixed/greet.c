#include <stdio.h>
#include <string.h>

/* Build a greeting from an untrusted name into a fixed 16-byte stack buffer.
   FIXED: snprintf is bounded by sizeof buf, truncating names to 15 bytes plus
   a NUL terminator, so no write can land past the end of buf. */
int format_greeting(const char *name, char *out, int outcap) {
    char buf[16];
    snprintf(buf, sizeof buf, "%s", name);
    return snprintf(out, outcap, "hi %s", buf);
}
