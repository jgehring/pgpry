/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: sysutils/sysutils.cpp
 * Various system utilities and wrapper classes
 */


#include "sysutils.h"


namespace SysUtils
{

// Constructor
Regex::Regex(const std::string &pattern)
	: m_pattern(pattern)
{
	// No support for extended regexes yet (may be added if needed)
	int32_t err = regcomp(&m_rx, pattern.c_str(), REG_NOSUB);
	if (err != 0) {
		throw errorString(err);
	}
}

// Copy constructor
Regex::Regex(const Regex &other)
{
	*this = other;
}

// Destructor
Regex::~Regex()
{
	regfree(&m_rx);
}

// Assignment operator
Regex &Regex::operator=(const Regex &other)
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

// Wrapper for regerror()
std::string Regex::errorString(int32_t error)
{
	char buf[128];
	regerror(error, &m_rx, buf, 128);
	return std::string(buf, 128);
}

} // namespace SysUtils
