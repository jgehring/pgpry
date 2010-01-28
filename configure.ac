#
# pgpry 0.1 - PGP private key password recovery
# Copyright (C) 2010 Jonas Gehring
#
# Process this file with autoconf to produce a configure script.
#

AC_PREREQ([2.63])
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
# Checks for headers
#



#
# Checks for system characteristics
#

AC_C_BIGENDIAN()



#
# Checks for libraries
#

# Pthread
AX_PTHREAD()
AC_SUBST([PTHREAD_LIBS])
AC_SUBST([PTHREAD_CFLAGS])
AC_SUBST([PTHREAD_CC])

# OpenSSL
AX_CHECK_OPENSSL()
AC_SUBST([OPENSSL_INCLUDES])
AC_SUBST([OPENSSL_LIBS])
AC_SUBST([OPENSSL_LDFLAGS])


AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT()
