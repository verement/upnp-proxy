
CC	= gcc
CFLAGS	= -O2 -Wall -Werror
LDFLAGS	= -lnetfilter_conntrack

upnp-proxy: main.o
	$(CC) $(LDFLAGS) -o $@ $^
	sudo setcap CAP_NET_ADMIN+ep $@
