/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: guessers.cpp
 * Guesser thread definition and factory
 */


#include <iostream>

#include "buffer.h"
#include "watch.h"

#include "guessers.h"

#include "incguesser.h"


namespace Guessers
{

// Constructor
Guesser::Guesser(Buffer *buffer)
	: Thread(), m_buffer(buffer)
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

	Watch watch;
	uint32_t n = 0;

	Memblock block;
	while (guess(&block)) {
		m_buffer->put(block);
		++n;

		if (watch.elapsed() > 2000) {
			std::cout << "Rate: " << 1000 * (double)n/watch.elapsed() << " phrases / second. ";
			std::cout << "Phrase: " << block.data << std::endl;
			watch.start();
			n = 0;
		}
	}
}

// Initializes the guesser
bool Guesser::init()
{
	// The default implementation does nothing
	return true;
}


// Returns a guesser using the given name
Guesser *guesser(const std::string &name, Buffer *buffer)
{
	if (name == "incremental") {
		return new IncrementalGuesser(buffer);
	}
	return NULL;
}

} // namespace Guessers
