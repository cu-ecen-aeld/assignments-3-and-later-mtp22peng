CC ?= $(CROSS_COMPILE)gcc
LDFLAGS ?= -lpthread
CFLAGS ?= -Wall -Werror -O2 -g
override CFLAGS += -DUSE_AESD_CHAR_DEVICE

all: aesdsocket

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket $(LDFLAGS)

.PHONY: clean

clean:
	rm -rf aesdsocket
