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
 * file: sysutils/sysutils.cpp
 * Various system utilities and wrapper classes
 */


#include <iostream>

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


// Constructor
Watch::Watch()
{
	start();
}

// Starts the stop watch
void Watch::start()
{
	gettimeofday(&m_tv, NULL);
}


// Constructor
SigHandler::SigHandler()
{

}

// Blocks the given signal
bool SigHandler::block(int32_t sig)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, sig);
	return pthread_sigmask(SIG_BLOCK, &set, NULL) == 0;
}

// Main thread loop
void SigHandler::run()
{
	int32_t sig;
	sigset_t set;
	sigemptyset(&set);
	setup(&set);

	while (sigwait(&set, &sig) == 0) {
		if (!handle(sig)) {
			break;
		}
	}
}

} // namespace SysUtils
