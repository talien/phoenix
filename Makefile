CC=gcc
CFLAGS=-W -Wall -g `pkg-config --cflags gtk+-2.0` `pkg-config --cflags gthread-2.0`
LFLAGS=-lnetfilter_queue `pkg-config --libs gtk+-2.0` `pkg-config --libs gthread-2.0`
OBJS=nfqueue.o callback.o misc.o sockproc.o
nfqueue:$(OBJS)
	$(CC) -o $@ $(OBJS) $(LFLAGS)

.c.o: $(CC) -c @< $(CFLAGS)

clean:
	rm *.o
