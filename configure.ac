#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([phoenix], [0.1], [tusavik@gmail.com])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lnetfilter_queue':
AC_CHECK_LIB([netfilter_queue], [main])
PKG_CHECK_MODULES([DEPS],[glib-2.0 > 2.20 gthread-2.0 > 2.20])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([gettimeofday memset socket])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT([src/Makefile scripts/Makefile])
