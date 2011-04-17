CC=gcc
CFLAGS=-W -Wall -g `pkg-config --cflags gtk+-2.0` `pkg-config --cflags gthread-2.0`
LFLAGS=-lnetfilter_queue `pkg-config --libs gtk+-2.0` `pkg-config --libs gthread-2.0`
DOBJS=callback.o misc.o sockproc.o daemon.o serialize.o zones.o types.o
#COBJS=nfqueue.o serialize.o misc.o
all:daemon

#nfqueue:$(COBJS)
#	$(CC) -o $@ $(COBJS) $(LFLAGS)

daemon:$(DOBJS)
	$(CC) -o $@ $(DOBJS) $(LFLAGS)

.c.o: $(CC) -c @< $(CFLAGS)

clean:
	rm *.o
