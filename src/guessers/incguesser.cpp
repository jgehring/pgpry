/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: incguesser.cpp
 * Simple incremental guessing
 */


#include "memblock.h"

#include "incguesser.h"


namespace Guessers
{

// Constructor
IncrementalGuesser::IncrementalGuesser(Buffer *buffer)
	: CharsetGuesser(buffer), m_length(0), m_indexes(NULL)
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
	m_indexes = new uint32_t[m_maxlength];
	for (uint32_t i = 0; i < m_maxlength; i++) {
		m_indexes[i] = 0;
	}

	return true;
}

// Guesses a pass pharse and returns false if the search space is exhausted
bool IncrementalGuesser::guess(Memblock *m)
{
	// Determine next phrase
	int32_t i = m_length - 1;
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

	if (m->length != m_length) {
		m->resize(m_length);
	}
	for (uint32_t j = 0; j < m_length; j++) {
		m->data[j] = m_charset[m_indexes[j]];
	}

	return true;
}

} // namespace Guessers
