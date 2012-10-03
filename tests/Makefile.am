sources = ../src/callback.c ../src/zones.c ../src/types.c ../src/misc.c ../src/serialize.c ../src/sockproc.c ../src/apptable.c ../src/config.c ../src/nfqueue.c
LDADD = $(DEPS_LIBS)
CFLAGS = $(DEPS_CFLAGS) -I../src/ -g -O0

check_PROGRAMS = test
test_SOURCES = test.c $(sources)
TESTS = $(check_PROGRAMS)
