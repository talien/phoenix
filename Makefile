CC=gcc
CFLAGS=-lnetfilter_queue `pkg-config --cflags --libs gtk+-2.0` `pkg-config --cflags --libs gthread-2.0`
OBJS=nfqueue.o callback.o misc.o sockproc.o
nfqueue:$(OBJS)
	$(CC) -o $@ $(OBJS) $(CFLAGS)

.c.o: $(CC) -c @< $(CFLAGS)

clean:
	rm *.o
