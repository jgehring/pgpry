/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: randomguesser.cpp
 * Simple random guessing
 */


#include <openssl/rand.h>

#include "memblock.h"

#include "randomguesser.h"


namespace Guessers
{

// Constructor
RandomGuesser::RandomGuesser(Buffer *buffer)
	: CharsetGuesser(buffer), m_randbuf(NULL)
{

}

// Destructor
RandomGuesser::~RandomGuesser()
{
	delete[] m_randbuf;
}

// Initializes the guesser
bool RandomGuesser::init()
{
	if (!CharsetGuesser::init()) {
		return false;
	}

	// Buffer for random bytes: an integer for each word position
	// and an extra one for the length
	m_rblength = m_maxlength + 1;
	m_randbuf = new uint32_t[m_rblength];
	return true;
}

// Guesses a pass pharse and returns false if the search space is exhausted
bool RandomGuesser::guess(Memblock *m)
{
	// First, generate a block of random bytes
	RAND_pseudo_bytes((uint8_t *)m_randbuf, m_rblength * sizeof(uint32_t));

	// Determine password length and characters
	uint32_t length = m_minlength + (m_randbuf[0] % (m_maxlength - m_minlength + 1));
	if (m->length != length) {
		m->resize(length);
	}
	for (uint32_t i = 0; i < length; i++) {
		m->data[i] = m_charset[m_randbuf[i+1] % m_cslength];
	}

	return true;
}

} // namespace Guessers
