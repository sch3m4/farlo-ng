#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

FULL-PACKAGE-NAME=farlo-ng
VERSION=0.5.8b
BUG-REPORT-ADDRESS=chema@safetybits.net

AC_PREREQ([2.69])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([subdir-objects])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

# Checks for libraries.
#AC_CHECK_LIB([pthread],[ssl], [rt], [xml], [pcap])
AC_CHECK_LIB(pthread, pthread_create, [], [ echo "ERROR!: libpthread not found!"; exit -1], [])
AC_CHECK_LIB(xml2, xmlParseFile, [], [ echo "ERROR!: libxml2 not found!"; exit -1], [])
AC_CHECK_LIB(ssl, MD5, [], [ echo "ERROR!: libssl not found!"; exit -1], [])
AC_CHECK_LIB(rt, clock_gettime, [], [ echo "ERROR!: librt not found!"; exit -1], [])
AC_CHECK_LIB(pcap, pcap_fileno, [], [ echo "ERROR!: libpcap not found!"; exit -1], [])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([clock_gettime inet_ntoa memset regcomp strcasecmp strchr strdup strerror strstr])

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT
