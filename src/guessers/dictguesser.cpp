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
 * file: dictguesser.cpp
 * Simple dictionary guesser
 */


#include <fstream>
#include <iostream>

#include "utils.h"

#include "dictguesser.h"


namespace Guessers
{

// Constructor
DictionaryGuesser::DictionaryGuesser(Buffer *buffer)
	: Guesser(buffer), m_index(0)
{

}

// Sets up the guesser according to the given options
void DictionaryGuesser::setup(const std::map<std::string, std::string> &options)
{
	std::map<std::string, std::string>::const_iterator it;

	m_dictfile = std::string();
	it = options.find("dictionary");
	if (it != options.end()) {
		m_dictfile = (*it).second;
	}

	m_index = 0;
	m_phrases.clear();
}

// Returns a list of all supported options
std::vector<std::pair<std::string, std::string> > DictionaryGuesser::options() const
{
	typedef std::pair<std::string, std::string> strpair_t;
	std::vector<strpair_t> opts = Guesser::options();
	opts.push_back(strpair_t("dictionary", "Dictionary file"));
	return opts;
}

// Initializes the guesser
void DictionaryGuesser::init()
{
	std::ifstream in(m_dictfile.c_str());
	if (in.fail()) {
		throw Utils::strprintf("Unable to open file %s", m_dictfile.c_str());
	}

	std::string str;
	while (in.good()) {
		getline(in, str);

		if (!str.empty()) {
			m_phrases.push_back(Memblock(str.c_str()));
		}
	}
}

// Guesses a pass pharse and returns false if the search space is exhausted
bool DictionaryGuesser::guess(Memblock *m)
{
	if (m_index >= m_phrases.size()) {
		return false;
	}

	*m = m_phrases[m_index++];
	return true;
}

} // namespace Guessers
