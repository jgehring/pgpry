#
# pgpry 0.1 - PGP private key password recovery
# Copyright (C) 2010 Jonas Gehring
#

bin_PROGRAMS = pgpry

pgpry_SOURCES = \
	cryptutils.h cryptutils.cpp \
	key.h key.cpp \
	main.h main.cpp \
	packetheader.h packetheader.cpp \
	pistream.h pistream.cpp \
	string2key.h string2key.cpp \
	thread.h thread.cpp \
	\
	crackers/crackers.h crackers/crackers.cpp \
	crackers/cast5crackers.h crackers/cast5crackers.cpp 


CC = $(PTHREAD_CC)

INCLUDES = \
	-Icrackers \
	$(OPENSSL_INCLUDES)

AM_CXXFLAGS = \
	-Wall -pipe \
    $(PTHREAD_CFLAGS)

AM_LDFLAGS = \
	$(OPENSSL_LDFLAGS)

LIBS += \
	$(PTHREAD_LIBS) \
	$(OPENSSL_LIBS)
