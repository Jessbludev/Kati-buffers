CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2 -Iinclude
LDFLAGS ?=

.PHONY: all test cli clean

all: test cli

src/kati.o: src/kati.c include/kati.h
	$(CC) $(CFLAGS) -c src/kati.c -o src/kati.o

test: src/kati.o tests/test.c
	$(CC) $(CFLAGS) tests/test.c src/kati.o -o tests/test
	./tests/test

cli: src/kati.o src/cli.c
	$(CC) $(CFLAGS) src/cli.c src/kati.o -o kati

clean:
	rm -f src/kati.o tests/test kati
