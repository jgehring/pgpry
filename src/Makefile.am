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
	guessers/charsetguesser.h guessers/charsetguesser.cpp \
	guessers/incguesser.h guessers/incguesser.cpp \
	guessers/randomguesser.h guessers/randomguesser.cpp \
	guessers/dictguesser.h guessers/dictguesser.cpp \
	\
	crackers/crackers.h crackers/crackers.cpp \
	crackers/sha1cracker.h crackers/sha1cracker.cpp \
	\
	sysutils/sysutils.h sysutils/sysutils.cpp \
	sysutils/threads.h sysutils/threads.cpp

INCLUDES = \
	-I@top_srcdir@/src/guessers \
	-I@top_srcdir@/src/crackers \
	-I@top_srcdir@/src/sysutils \
	$(OPENSSL_INCLUDES)

AM_CXXFLAGS = \
	-Wall -pipe -ansi \
    $(PTHREAD_CFLAGS)

AM_CPPFLAGS =

AM_LDFLAGS = \
	$(OPENSSL_LDFLAGS)

LIBS += \
	$(PTHREAD_LIBS) \
	$(OPENSSL_LIBS)


# Optional features
if BLOCK_SHA1
pgpry_SOURCES += \
	3rdparty/block-sha1/block-sha1.h 3rdparty/block-sha1/block-sha1.cpp
AM_CPPFLAGS += -DUSE_BLOCK_SHA1
endif
