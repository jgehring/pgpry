/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: guessers.cpp
 * Guesser thread definition and factory
 */


#include <iostream>

#include "guessers.h"

#include "incguesser.h"


namespace Guessers
{

// Constructor
Guesser::Guesser()
	: Thread()
{

}

// Sets up the guesser according to the given options
void Guesser::setup(const std::map<std::string, std::string> &)
{
	// The default implementation does nothing
}

// Main thread loop
void Guesser::run()
{
	if (!init()) {
		std::cerr << "Error initializing guesser!" << std::endl;
		return;
	}
}

// Initializes the guesser
bool Guesser::init()
{
	// The default implementation does nothing
	return true;
}


// Returns a guesser using the given name
Guesser *guesser(const std::string &name)
{
	Guesser *g = new IncrementalGuesser();
	return g;
}

} // namespace Guessers
