sbin_PROGRAMS = phoenixd

noinst_LTLIBRARIES = libphoenix.la

libphoenix_la_SOURCES = src/callback.c src/zones.c src/types.c src/misc.c src/serialize.c src/sockproc.c src/apptable.c src/config.c src/nfqueue.c

libphoenix_la_CFLAGS = $(DEPS_CFLAGS) $(NFQ_CFLAGS) -O0 -ggdb3
libphoenix_la_LIBADD = $(DEPS_LIBS) $(NFQ_LIBS)

phoenixd_SOURCES = src/daemon.c
phoenixd_CFLAGS = $(DEPS_CFLAGS)
phoenixd_LDADD = libphoenix.la $(DEPS_LIBS)
