CC=gcc
CFLAGS=-Wall -g `pkg-config --cflags --libs gtk+-2.0` `pkg-config --cflags --libs gthread-2.0`
LFLAGS=-lnetfilter_queue 
OBJS=nfqueue.o callback.o misc.o sockproc.o
nfqueue:$(OBJS)
	$(CC) -o $@ $(OBJS) $(CFLAGS) $(LFLAGS)

.c.o: $(CC) -c @< $(CFLAGS)

clean:
	rm *.o
