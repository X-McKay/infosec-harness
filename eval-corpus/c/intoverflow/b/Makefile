# Build and run the dup_n test under AddressSanitizer when available.
# The workspace ships gcc with the ASan runtime; macOS clang also supports it.
CC ?= cc
CFLAGS ?= -g -O0 -fsanitize=address -fno-omit-frame-pointer

dup_test: dup.c test_dup.c
	$(CC) $(CFLAGS) -o dup_test dup.c test_dup.c

.PHONY: test clean
test: dup_test
	./dup_test

clean:
	rm -f dup_test
