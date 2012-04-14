
CC	= gcc
CFLAGS	= -O2 -Wall

upnp-proxy: main.o
	$(CC) -o $@ $^
