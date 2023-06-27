ifeq ($(CROSS_COMPILE),aarch64-none-linux-gnu-)
   CC = $(CROSS_COMPILE)"gcc"
else
#   CC = gcc
#

   CC = $(CROSS_COMPILE)"gcc"
endif



all:	aesdsocket


CFLAGS= -Wall -W -O2 -g -Werror 
LDFLAGS += -L./libs -pthread  -lrt 

# aesdsocket &: aesdsocket.c
#	$(CC) -o aesdsocket aesdsocket.c



aesdsocket: aesdsocket.c
	$(CC) $(INCLUDES) $(CFLAGS) -c aesdsocket.c -o aesdsocket.o
	$(CC) $(LIBS) aesdsocket.o -o aesdsocket $(LDFLAGS) 


clean:
	rm -f aesdsocket.o aesdsocket

