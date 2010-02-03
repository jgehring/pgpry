#
# pgpry 0.1 - PGP private key password recovery
# Copyright (C) 2010 Jonas Gehring
#

bin_PROGRAMS = pgpry

pgpry_SOURCES = \
	buffer.h buffer.cpp \
	cryptutils.h cryptutils.cpp \
	key.h key.cpp \
	main.h main.cpp \
	memblock.h \
	mutex.h mutex.cpp \
	options.h options.cpp \
	packetheader.h packetheader.cpp \
	pistream.h pistream.cpp \
	pregex.h pregex.cpp \
	psemaphore.h psemaphore.cpp \
	regexfilter.h regexfilter.cpp \
	string2key.h string2key.cpp \
	thread.h thread.cpp \
	utils.h utils.cpp \
	watch.h watch.cpp \
	\
	guessers/guessers.h guessers/guessers.cpp \
	guessers/charsteguesser.h guessers/charsetguesser.cpp \
	guessers/incguesser.h guessers/incguesser.cpp \
	\
	crackers/crackers.h crackers/crackers.cpp \
	crackers/cast5crackers.h crackers/cast5crackers.cpp 


CC = $(PTHREAD_CC)

INCLUDES = \
	-Iguessers \
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
