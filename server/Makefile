ifndef CROSS_COMPILE
	CC=gcc
else
	CC=$(CROSS_COMPILE)gcc
endif


INCLUDES:= -I ./include
LIBS:=
CFLAGS += -g -Wall -Werror -pthread -o

LDFLAGS += -lpthread -lrt
LIBS=-pthread

all:	aesdsocket
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS) aesdsocket.c $(LIBS) 

clean:
	rm -rf *.o aesdsocket
