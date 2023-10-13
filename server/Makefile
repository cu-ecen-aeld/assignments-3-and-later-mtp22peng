CC ?= $(CROSS_COMPILE)gcc
LDFLAGS ?= -lpthread
CFLAGS ?= -Wall -Werror -O2 -g
override CFLAGS += -DUSE_AESD_CHAR_DEVICE

default:
	${CC} $(CFLAGS) -o aesdsocket aesdsocket.c $(LDFLAGS)
all:
	${CC} -pthread -Wall -o aesdsocket aesdsocket.c

.PHONY: clean

clean:
	rm -rf aesdsocket
