CC ?= ${CROSS_COMPILE}gcc

CFLAGS ?= -c -Wall -Werror -pthread

TARGET ?= aesdsocket

LDFLAGS ?= -lpthread -lrt

.DEFAULT_GOAL := aesdsocket

all: aesdsocket
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS) aesdsocket.c

.PHONY: clean
clean: 
	rm -f aesdsocket *.o *.c~ *.h~
