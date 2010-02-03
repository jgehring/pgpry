/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: main.cpp
 * Program entry point
 */


#include <cstdlib>
#include <iostream>

#include "buffer.h"
#include "crackers.h"
#include "guessers.h"
#include "key.h"
#include "options.h"
#include "pistream.h"
#include "regexfilter.h"


// Program entry point
int main(int argc, char **argv)
{
	// Parse options
	Options options;
	try {
		options.parse(argc, argv);
	} catch (const std::string &str) {
		std::cerr << "Error parsing arguments: " << str << std::endl;
		return EXIT_FAILURE;
	} catch (const char *cstr) {
		std::cerr << "Error parsing arguments: " << cstr << std::endl;
		return EXIT_FAILURE;
	}

	if (options.helpRequested()) {
		options.printHelp();
		return EXIT_SUCCESS;
	} else if (options.versionRequested()) {
		options.printVersion();
		return EXIT_SUCCESS;
	}

	// Read key from stdin
	Key key;
	try {
		PIStream in(std::cin);
		in >> key;
	} catch (const std::string &str) {
		std::cerr << "Exception while parsing key: " << str << std::endl;
		return EXIT_FAILURE;
	} catch (const char *cstr) {
		std::cerr << "Exception while parsing key: " << cstr << std::endl;
		return EXIT_FAILURE;
	}

	if (!key.locked()) {
		std::cerr << "Err, this secret key doesn't seem to be encrypted" << std::endl;
		return EXIT_FAILURE;
	}

	// Test, test
	Buffer buffer;
	Guessers::Guesser *guesser = Guessers::guesser(options.guesser(), &buffer);
	if (guesser == NULL) {
		std::cerr << "Error: Unkown guessing method " << options.guesser() << std::endl;
		return EXIT_FAILURE;
	}
	guesser->setup(options.guesserOptions());
	guesser->start();

	// Hm, quite a lot of crackers
	Crackers::Cracker *cracker = Crackers::crackerFor(key, &buffer);
	if (cracker) {
		cracker->start();
		cracker->wait();
	} else {
		std::cerr << "Error: Unsupported hash or cipher algorithm" << std::endl;
		std::cerr << (int)key.string2Key().hashAlgorithm() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
