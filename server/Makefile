
CC ?= $(CROSS_COMPILE)gcc

all:	aesdsocket

LIBS:= -L./libs 
CFLAGS ?= -Wall -W -O2 -g -Werror 
LDFLAGS ?=  -pthread  -lrt 

# aesdsocket &: aesdsocket.c
#	$(CC) -o aesdsocket aesdsocket.c



aesdsocket: aesdsocket.c
	$(CC) $(INCLUDES) $(CFLAGS) -c aesdsocket.c -o aesdsocket.o
	$(CC) $(LIBS) aesdsocket.o -o aesdsocket $(LDFLAGS) 


clean:
	rm -f aesdsocket.o aesdsocket

