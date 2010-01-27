#
# pgpry 0.1 - PGP private key password recovery
# Copyright (C) 2010 Jonas Gehring
#

bin_PROGRAMS = pgpry

pgpry_SOURCES = \
	main.cpp


INCLUDES = \
    $(OPENSSL_INCLUDES)

AM_CXXFLAGS = \
	-Wall -pipe

AM_LDFLAGS = \
	$(OPENSSL_LDFLAGS)

LIBS += \
	$(OPENSSL_LIBS)
