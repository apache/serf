# this is just for testing... we'll get a "real" build system at some point
#
# add apr-config and apu-config to your PATH before invoking this Makefile
#

OBJECTS = buckets/aggregate_buckets.o buckets/request_buckets.o context.o \
          buckets/buckets.o buckets/simple_buckets.o buckets/file_buckets.o \
          buckets/mmap_buckets.o buckets/socket_buckets.o \
          buckets/response_buckets.o \
          test/serf_get.o
PROGRAMS = test/serf_get

# Place apr-config and apu-config in your PATH.
APR_CONFIG=apr-1-config
APU_CONFIG=apu-1-config

CC = `$(APR_CONFIG) --cc`
CFLAGS = `$(APR_CONFIG) --cflags`
CPPFLAGS = `$(APR_CONFIG) --cppflags`
INCLUDES = -I`pwd` `$(APR_CONFIG) --includes`

LDFLAGS = `$(APR_CONFIG) --ldflags` `$(APU_CONFIG) --ldflags`
LIBS = `$(APR_CONFIG) --link-ld --libs` `$(APU_CONFIG) --link-ld --libs`

all: $(OBJECTS) $(PROGRAMS)

context.o: context.c
buckets/aggregate_buckets.o: buckets/aggregate_buckets.c
buckets/request_buckets.o: buckets/request_buckets.c
buckets/buckets.o: buckets/buckets.c
buckets/simple_buckets.o: buckets/simple_buckets.c

test/serf_get: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(OBJECTS) $(PROGRAMS)

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c -o $@ $<
