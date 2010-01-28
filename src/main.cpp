/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: main.cpp
 * Program entry point
 */


#include <cstdlib>
#include <iostream>

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

	return EXIT_SUCCESS;
}
