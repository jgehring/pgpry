#
# pgpry - PGP private key recovery
# Copyright (C) 2010 Jonas Gehring
#

bin_PROGRAMS = utests
utests_SOURCES = \
	main.cpp \
	test_confio.cpp \
	test_memblock.cpp \
	test_utils.cpp \
	\
	$(top_srcdir)/src/confio.cpp \
	$(top_srcdir)/src/utils.cpp

AM_CXXFLAGS = -Wall -pipe -ansi -I$(top_srcdir)/src
