CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -fPIE -pie

all: boxbpf

boxbpf: main.c loader.c config.c common.h compat.h
	$(CC) $(CFLAGS) main.c loader.c config.c -o $@

clean:
	rm -f boxbpf

.PHONY: all clean
