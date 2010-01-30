/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: incguesser.cpp
 * Simple incremental guessing
 */


#include "incguesser.h"


namespace Guessers
{

// Constructor
IncrementalGuesser::IncrementalGuesser()
	: CharsetGuesser(), m_length(0), m_indexes(NULL)
{

}

// Destructor
IncrementalGuesser::~IncrementalGuesser()
{
	delete[] m_indexes;
}

// Initializes the guesser
bool IncrementalGuesser::init()
{
	if (!CharsetGuesser::init()) {
		return false;
	}

	m_length = m_minlength;
	m_indexes = new uint32_t[m_length];
	for (uint32_t i = 0; i < m_length; i++) {
		m_indexes[i] = 0;
	}

	return true;
}

// Guesses a pass pharse and returns false if the search space is exhausted
bool IncrementalGuesser::guess()
{
	// Determine next phrase
	uint32_t i = m_length - 1;
	while (++m_indexes[i] >= m_cslength) {
		m_indexes[i] = 0;
		if (--i < 0) {
			if (++m_length > m_maxlength) {
				return false;
			}
			for (uint32_t j = 0; j < m_length; j++) {
				m_indexes[j] = 0;
			}
			break;
		}
	}

	return true;
}

} // namespace Guessers
