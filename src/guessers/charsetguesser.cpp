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
 * file: charsetguessers.cpp
 * Base class for charset guessers
 */


#include <cstring>
#include <ctype.h>

#include "utils.h"

#include "charsetguesser.h"

#define DEFAULT_MIN 1
#define DEFAULT_MAX 10


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
		m_charset = new uint8_t[256];
		for (int32_t i = 0; i < 255; i++) {
			if (isprint(i)) {
				m_charset[m_cslength++] = (uint8_t)i;
			}
		}
	}

	m_minlength = Utils::defaultOption(options, "min", DEFAULT_MIN);
	m_maxlength = Utils::defaultOption(options, "max", DEFAULT_MAX);
	it = options.find("min");
	if (it != options.end()) {
		uint32_t t;
		if (Utils::str2int((*it).second, &t)) {
			m_minlength = t;
		}
	}
	it = options.find("max");
	if (it != options.end()) {
		uint32_t t;
		if (Utils::str2int((*it).second, &t)) {
			m_maxlength = t;
		}
	}
}

// Returns a list of all supported options
std::vector<std::pair<std::string, std::string> > CharsetGuesser::options() const
{
	typedef std::pair<std::string, std::string> strpair_t;
	std::vector<strpair_t> opts = Guesser::options();
	opts.push_back(strpair_t("charset", "Chacter set (default: all printable characters)"));
	opts.push_back(strpair_t("min", Utils::strprintf("Minimum password length (default: %d)", DEFAULT_MIN)));
	opts.push_back(strpair_t("max", Utils::strprintf("Maximum password length (default: %d)", DEFAULT_MAX)));
	return opts;
}

// Initializes the guesser
void CharsetGuesser::init()
{
	if (m_charset == NULL) {
		throw "Guesser's character set not initialized";
	}
	if (m_minlength > m_maxlength) {
		throw "Minimum password length bigger than maximum password length";
	}
}

} // namespace Guessers
