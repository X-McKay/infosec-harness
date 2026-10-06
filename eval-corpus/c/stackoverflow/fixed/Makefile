# Build and run the greeting test under AddressSanitizer when available.
# The workspace ships gcc with the ASan runtime; macOS clang also supports it.
CC ?= cc
CFLAGS ?= -g -O0 -fsanitize=address -fno-omit-frame-pointer -fstack-protector-all

greet_test: greet.c test_greet.c
	$(CC) $(CFLAGS) -o greet_test greet.c test_greet.c

.PHONY: test clean
test: greet_test
	./greet_test

clean:
	rm -f greet_test
