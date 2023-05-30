ifeq ($(CROSS_COMPILE),aarch64-none-linux-gnu-)
   CC = $(CROSS_COMPILE)"gcc"
else
   CC = gcc
endif



all:	aesdsocket


CFLAGS= -Wall -W -O2 -lrt -g -Werror -pthread 

 aesdsocket &: aesdsocket.c
	$(CC) -o aesdsocket aesdsocket.c

clean:
	rm -f aesdsocket.o aesdsocket

