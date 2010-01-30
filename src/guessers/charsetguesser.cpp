/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: charsetguessers.cpp
 * Base class for charset guessers
 */


#include <cstring>
#include <ctype.h>

#include "utils.h"

#include "charsetguesser.h"


namespace Guessers
{

// Constructor
CharsetGuesser::CharsetGuesser(Buffer *buffer)
	: Guesser(buffer), m_charset(NULL), m_cslength(0), m_minlength(0), m_maxlength(0)
{

}

// Destructor
CharsetGuesser::~CharsetGuesser()
{
	delete[] m_charset;
}

// Sets up the guesser according to the given options
void CharsetGuesser::setup(const std::map<std::string, std::string> &options)
{
	std::map<std::string, std::string>::const_iterator it;

	delete[] m_charset;
	it = options.find("charset");
	if (it != options.end()) {
		m_cslength = (*it).second.length();
		m_charset = new uint8_t[m_cslength];
		memcpy(m_charset, (*it).second.c_str(), m_cslength);
	} else {
		m_cslength = 0;
		m_charset = new uint8_t[255];
		for (int32_t i = 0; i < 255; i++) {
			if (isalpha(i) || isspace(i) || ispunct(i)) {
				m_charset[m_cslength++] = (uint8_t)i;
			}
		}
	}

	m_minlength = 1;
	it = options.find("min");
	if (it != options.end()) {
		uint32_t t;
		if (Utils::str2int((*it).second, &t)) {
			m_minlength = t;
		}
	}

	m_maxlength = 10;
	it = options.find("max");
	if (it != options.end()) {
		uint32_t t;
		if (Utils::str2int((*it).second, &t)) {
			m_maxlength = t;
		}
	}
}

// Initializes the guesser
bool CharsetGuesser::init()
{
	return (m_charset != NULL && m_minlength < m_maxlength);
}

} // namespace Guessers
