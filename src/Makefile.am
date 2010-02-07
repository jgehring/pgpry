#
# pgpry 0.1 - PGP private key password recovery
# Copyright (C) 2010 Jonas Gehring
#

bin_PROGRAMS = pgpry

pgpry_SOURCES = \
	attack.h attack.cpp \
	buffer.h buffer.cpp \
	cryptutils.h cryptutils.cpp \
	key.h key.cpp \
	main.h main.cpp \
	memblock.h \
	options.h options.cpp \
	packetheader.h packetheader.cpp \
	pistream.h pistream.cpp \
	regexfilter.h regexfilter.cpp \
	string2key.h string2key.cpp \
	utils.h utils.cpp \
	watch.h watch.cpp \
	\
	guessers/guessers.h guessers/guessers.cpp \
	guessers/charsteguesser.h guessers/charsetguesser.cpp \
	guessers/incguesser.h guessers/incguesser.cpp \
	guessers/randomguesser.h guessers/randomguesser.cpp \
	\
	crackers/crackers.h crackers/crackers.cpp \
	crackers/cast5crackers.h crackers/cast5crackers.cpp \
	\
	sysutils/sysutils.h sysutils/sysutils.cpp \
	sysutils/threads.h sysutils/threads.cpp


CC = $(PTHREAD_CC)

INCLUDES = \
	-Iguessers \
	-Icrackers \
	-Isysutils \
	$(OPENSSL_INCLUDES)

AM_CXXFLAGS = \
	-Wall -pipe \
    $(PTHREAD_CFLAGS)

AM_LDFLAGS = \
	$(OPENSSL_LDFLAGS)

LIBS += \
	$(PTHREAD_LIBS) \
	$(OPENSSL_LIBS)
