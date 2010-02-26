#
# pgpry - PGP private key recovery
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
	\
	guessers/guessers.h guessers/guessers.cpp \
	guessers/charsteguesser.h guessers/charsetguesser.cpp \
	guessers/incguesser.h guessers/incguesser.cpp \
	guessers/randomguesser.h guessers/randomguesser.cpp \
	guessers/dictguesser.h guessers/dictguesser.cpp \
	\
	crackers/crackers.h crackers/crackers.cpp \
	crackers/sha1cracker.h crackers/sha1cracker.cpp \
	\
	sysutils/sysutils.h sysutils/sysutils.cpp \
	sysutils/threads.h sysutils/threads.cpp \
	\
	3rdparty/block-sha1/sha1.h 3rdparty/block-sha1/sha1.cpp


CC = $(PTHREAD_CC)

AM_CPPFLAGS = 
if BLOCK_SHA1
AM_CPPFLAGS += -DUSE_BLOCK_SHA1
endif

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
