# this is just for testing... we'll get a "real" build system at some point
#
# add apr-config and apu-config to your PATH before invoking this Makefile
#

OBJECTS = buckets/aggregate_buckets.o buckets/request_buckets.o context.o \
          buckets/buckets.o buckets/simple_buckets.o

# Place apr-config and apu-config in your PATH.
APR_CONFIG=apr-config
APU_CONFIG=apu-config

CC = `$(APR_CONFIG) --cc`
CFLAGS = `$(APR_CONFIG) --cflags`
CPPFLAGS = `$(APR_CONFIG) --cppflags`
INCLUDES = -I`pwd` `$(APR_CONFIG) --includes`

all: $(OBJECTS)

context.o: context.c
buckets/aggregate_buckets.o: buckets/aggregate_buckets.c
buckets/request_buckets.o: buckets/request_buckets.c
buckets/buckets.o: buckets/buckets.c
buckets/simple_buckets.o: buckets/simple_buckets.c

clean:
	rm -f $(OBJECTS)

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c -o $@ $<
