#
# pgpry - PGP private key recovery
# Copyright (C) 2010 Jonas Gehring
#
# Process this file with autoconf to produce a configure script.
#

AC_PREREQ([2.6])
AC_INIT(pgpry, 0.1.1, jonas.gehring@boolsoft.org)
AM_INIT_AUTOMAKE()
AC_CONFIG_HEADER([config.h])
AC_CONFIG_TESTDIR([tests])

sinclude(m4/ax_check_openssl.m4)
sinclude(m4/ax_pthread.m4)


#
# Checks for programs
#

AC_PROG_CXX()
AC_PROG_CC()
AC_PROG_INSTALL()


#
# Checks for types
#

AC_TYPE_INT8_T()
AC_TYPE_INT16_T()
AC_TYPE_INT32_T()
AC_TYPE_UINT8_T()
AC_TYPE_UINT16_T()
AC_TYPE_UINT32_T()


#
# Checks for system and compiler characteristics
#

AC_C_BIGENDIAN()


#
# Checks for headers
#

AC_CHECK_HEADERS([signal.h])
AC_CHECK_HEADERS([sys/time.h])


#
# Checks for functions
#

AC_FUNC_MALLOC()
AC_CHECK_FUNCS([gettimeofday memset strtol])
AC_CHECK_FUNCS([regcomp])


#
# Checks for libraries
#

# Pthread
AX_PTHREAD()

# OpenSSL
AX_CHECK_OPENSSL()


#
# Optional features
#

AC_ARG_ENABLE([block-sha1], [AS_HELP_STRING([--enable-block-sha1], [Use block-sha1 algorithm from git (default is no)])], [blocksha1="$enableval"], [blocksha1="no"])
AM_CONDITIONAL([BLOCK_SHA1], [test "x$blocksha1" = "xyes"])


#
# End
#

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	tests/Makefile
	tests/atlocal
	tests/utests/Makefile
])
AC_OUTPUT()
