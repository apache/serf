# this is just for testing... we'll get a "real" build system at some point
#
# set the INCLUDES envvar before invoking this
#

OBJECTS = buckets/aggregate_buckets.o buckets/request_buckets.o context.o \
          buckets/buckets.o buckets/simple_buckets.o

CFLAGS = -g -Wall -Wmissing-prototypes -Wstrict-prototypes  \
         -Wmissing-declarations -Wpointer-arith -Wwrite-strings \
         -Wshadow -std=c89 \
         -pthread
CPPFLAGS = -DLINUX=2 -D_REENTRANT -D_XOPEN_SOURCE=500 -D_BSD_SOURCE -D_SVID_SOURCE -D_GNU_SOURCE

all: $(OBJECTS)

context.o: context.c
buckets/aggregate_buckets.o: buckets/aggregate_buckets.c
buckets/request_buckets.o: buckets/request_buckets.c
buckets/buckets.o: buckets/buckets.c
buckets/simple_buckets.o: buckets/simple_buckets.c

clean:
	rm -f $(OBJECTS)

.c.o:
	gcc $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c -o $@ $<
