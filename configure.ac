#
# pgpry 0.1 - PGP private key password recovery
# Copyright (C) 2010 Jonas Gehring
#
# Process this file with autoconf to produce a configure script.
#

AC_PREREQ([2.6])
AC_INIT(pgpry, alpha, jonas.gehring@boolsoft.org)
AM_INIT_AUTOMAKE()
AC_CONFIG_HEADER([config.h])

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


AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT()
