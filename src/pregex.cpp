/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: pregex.cpp
 * Simple regular expression class using POSIX regex
 */


#include "pregex.h"


// Constructor
PRegex::PRegex(const std::string &pattern)
	: m_pattern(pattern)
{
	// No support for extended regexes yet (may be added if needed)
	int32_t err = regcomp(&m_rx, pattern.c_str(), REG_NOSUB);
	if (err != 0) {
		throw errorString(err);
	}
}

// Copy constructor
PRegex::PRegex(const PRegex &other)
{
	*this = other;
}

// Destructor
PRegex::~PRegex()
{
	regfree(&m_rx);
}

// Assignment operator
PRegex &PRegex::operator=(const PRegex &other)
{
	if (!m_pattern.empty()) {
		regfree(&m_rx);
	}
	m_pattern = other.m_pattern;
	// No support for extended regexes yet (may be added if needed)
	int32_t err = regcomp(&m_rx, m_pattern.c_str(), REG_NOSUB);
	if (err != 0) {
		throw errorString(err);
	}
	return *this;
}

// Wrapper for
std::string PRegex::errorString(int32_t error)
{
	char buf[128];
	regerror(error, &m_rx, buf, 128);
	return std::string(buf, 128);
}
