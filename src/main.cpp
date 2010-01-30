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
#include "guessers.h"
#include "crackers.h"
#include "key.h"
#include "pistream.h"


// Program entry point
int main(int argc, char **argv)
{
	// Read key from stdin
	Key key;
	try {
		PIStream in(std::cin);
		in >> key;
	} catch (const char *str) {
		std::cerr << "Exception while parsing key: " << str << std::endl;
		return EXIT_FAILURE;
	}

	if (!key.locked()) {
		std::cerr << "Err, this secret key doesn't seem to be encrypted" << std::endl;
		return EXIT_FAILURE;
	}

	std::map<std::string, std::string> options;

	// Test, test
	Buffer buffer;
	Guessers::Guesser *guesser = Guessers::guesser("incremental", &buffer);
	guesser->setup(options);
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
