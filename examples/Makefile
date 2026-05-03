CC ?= cc
CFLAGS := -g -O2 -Wall -Wextra -I../include
LDFLAGS := -L../build -Wl,-rpath,$(abspath ../build) -ltrawl_shim -pthread

.PHONY: all clean
all: demo_server sleep_bound_server

demo_server: demo_server.c ../include/trawl_marker.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

sleep_bound_server: sleep_bound_server.c ../include/trawl_marker.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f demo_server sleep_bound_server
