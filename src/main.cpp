/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: main.cpp
 * Program entry point
 */


#include <cstdlib>
#include <iostream>

#include "attack.h"
#include "key.h"
#include "options.h"
#include "pistream.h"


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

	// Let's go
	return Attack::run(key, options);
}
