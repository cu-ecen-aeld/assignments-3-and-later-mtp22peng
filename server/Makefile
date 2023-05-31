ifeq ($(CROSS_COMPILE),aarch64-none-linux-gnu-)
   CC = $(CROSS_COMPILE)"gcc"
else
   CC = gcc
endif



all:	aesdsocket


CFLAGS= -Wall -W -O2 -lrt -g -Werror 
LDFLAGS += -L./libs -pthread 

# aesdsocket &: aesdsocket.c
#	$(CC) -o aesdsocket aesdsocket.c



aesdsocket: aesdsocket.c
	$(CC) $(INCLUDES) $(CFLAGS) -c aesdsocket.c -o aesdsocket.o
	$(CC) $(LIBS) $(LDFLAGS) aesdsocket.o -o aesdsocket


clean:
	rm -f aesdsocket.o aesdsocket

