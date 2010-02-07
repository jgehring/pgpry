/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: dictguesser.cpp
 * Simple dictionary guesser
 */


#include <fstream>
#include <iostream>

#include "dictguesser.h"


namespace Guessers
{

// Constructor
DictionaryGuesser::DictionaryGuesser(Buffer *buffer)
	: Guesser(buffer), m_index(0)
{

}

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

bool DictionaryGuesser::init()
{
	std::ifstream in(m_dictfile.c_str());
	if (in.fail()) {
		std::cerr << "Error: Unable to open file " << m_dictfile << std::endl;
		return false;
	}

	std::string str;
	while (in.good()) {
		getline(in, str);

		if (!str.empty()) {
			m_phrases.push_back(Memblock(str.c_str()));
		}
	}

	return true;
}

bool DictionaryGuesser::guess(Memblock *m)
{
	if (m_index >= m_phrases.size()) {
		return false;
	}

	*m = m_phrases[m_index++];
	return true;
}

} // namespace Guessers
