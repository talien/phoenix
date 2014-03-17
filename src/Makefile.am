sbin_PROGRAMS = phoenixd

noinst_LTLIBRARIES = libphoenix.la

libphoenix_la_SOURCES = callback.c zones.c types.c misc.c serialize.c sockproc.c apptable.c config.c nfqueue.c

libphoenix_la_CFLAGS = $(DEPS_CFLAGS) $(NFQ_CFLAGS) -O0 -ggdb3
libphoenix_la_LIBADD = $(DEPS_LIBS) $(NFQ_LIBS)

phoenixd_SOURCES = daemon.c
phoenixd_CFLAGS = $(DEPS_CFLAGS)
phoenixd_LDADD = libphoenix.la $(DEPS_LIBS)
