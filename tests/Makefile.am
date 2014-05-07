
check_PROGRAMS = test
test_SOURCES = tests/test.c
test_LDADD = ${top_builddir}/src/libphoenix.la
test_CFLAGS = $(DEPS_CFLAGS) -I${top_srcdir}/src/
TESTS = $(check_PROGRAMS)

func-test:
	PHOENIXD_PATH=${top_builddir}/src ${top_srcdir}/tests/functional.py
