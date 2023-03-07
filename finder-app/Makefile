
# Platform Overrides
 CROSS_COMPILE  = HOST


ifeq ($(CROSS_COMPILE),aarch64-none-linux-gnu-)
   CC = $(CROSS_COMPILE)"gcc"
else
   CC = gcc
endif






CFLAGS= -Wall -W -O2 -lrt -g

writer write &: writer.c
	$(CC) -o writer writer.c
	$(CC) -o write writer.c

clean:
	rm -f writer.o writer write.o write
