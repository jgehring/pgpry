/*
 * pgpry - PGP private key recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * file: incguesser.cpp
 * Simple incremental guessing
 */


#include <confio.h>
#include <iostream>

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

// Saves the guesser state
void IncrementalGuesser::saveState(ConfWriter *writer) const
{
	CharsetGuesser::saveState(writer);

	writer->put("length", m_length);
	writer->put("indexes", m_indexes, m_maxlength);
	writer->put("has_next", m_hasNext);
}

// Loads the guesser state
void IncrementalGuesser::loadState(ConfReader *reader)
{
	CharsetGuesser::loadState(reader);

	delete[] m_indexes;
	m_indexes = NULL;

	do {
		if (reader->tag() == "length") {
			m_length = reader->getint();
		} else if (reader->tag() == "indexes") {
			m_indexes = new uint32_t[m_maxlength];
			reader->getints(m_indexes, m_maxlength);
		} else if (reader->tag() == "has_next") {
			m_hasNext = reader->getbool();
		} else if (!reader->tag().empty()) {
			break;
		}
	} while (reader->next());

	if (m_indexes == NULL) {
		throw "Tag 'indexes' is missing";
	}
}

// Initializes the guesser
void IncrementalGuesser::init()
{
	CharsetGuesser::init();

	m_length = m_minlength;
	m_indexes = new uint32_t[m_maxlength];
	for (uint32_t i = 0; i < m_maxlength; i++) {
		m_indexes[i] = 0;
	}
	m_hasNext = true;
}

// Guesses a pass pharse and returns false if the search space is exhausted
bool IncrementalGuesser::guess(Memblock *m)
{
	if (!m_hasNext) {
		return false;
	}

	if (m->length != m_length) {
		m->resize(m_length);
	}
	for (uint32_t j = 0; j < m_length; j++) {
		m->data[j] = m_charset[m_indexes[j]];
	}

	// Determine next phrase
	int32_t i = m_length - 1;
	while (++m_indexes[i] >= m_cslength) {
		m_indexes[i] = 0;
		if (--i < 0) {
			if (++m_length > m_maxlength) {
				m_hasNext = false;
				return true;
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
