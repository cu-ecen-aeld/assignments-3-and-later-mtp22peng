CC ?= $(CROSS_COMPILE)gcc


ifeq ($(USE_AESD_CHAR_DEVICE), 1)
DEFINE_AESD_CHAR_DEVICE = -DUSE_AESD_CHAR_DEVICE=1
else
DEFINE_AESD_CHAR_DEVICE =
endif
INCLUDES:= -I ./include
LIBS:= -L./libs 
CFLAGS ?= -g -Wall -Werror $(DEFINE_AESD_CHAR_DEVICE)
LDFLAGS ?= -lrt -pthread
TARGET ?= aesdsocket

all:	aesdsocket
default:aesdsocket

aesdsocket: aesdsocket.c utility_funcs.c ./include/utility.h
	$(CC) $(INCLUDES) $(CFLAGS) -c aesdsocket.c -o aesdsocket.o
	$(CC) $(INCLUDES) $(CFLAGS) -c utility_funcs.c -o utility_funcs.o
	$(CC) $(LIBS) utility_funcs.o aesdsocket.o -o ${TARGET} $(LDFLAGS) 

.PHONY: clean
clean:
	rm -rf *.o aesdsocket
