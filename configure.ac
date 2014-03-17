#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([phoenix], [0.1], [tusavik@gmail.com])
AM_INIT_AUTOMAKE

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([no])])

# Checks for programs.
AC_PROG_CC
PKG_PROG_PKG_CONFIG

LT_INIT([shared dlopen])

# Checks for libraries.
PKG_CHECK_MODULES(NFQ, libnetfilter_queue)
PKG_CHECK_MODULES([DEPS],[glib-2.0 > 2.20 gthread-2.0 > 2.20])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([gettimeofday memset socket])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT([src/Makefile scripts/Makefile tests/Makefile])
