#include <stdio.h>
#include <string.h>

/* Build a greeting from an untrusted name into a fixed 16-byte stack buffer.
   VULNERABLE: strcpy copies the whole name with no bound, so a name of 16
   bytes or more writes past the end of buf (CWE-121 stack buffer overflow). */
int format_greeting(const char *name, char *out, int outcap) {
    char buf[16];
    strcpy(buf, name);
    return snprintf(out, outcap, "hi %s", buf);
}
