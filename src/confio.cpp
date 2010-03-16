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
 * file: confio.cpp
 * Configuration file reading and writing
 *
 * The configuration file "format" is very simple (indentation added for
 * visual assistance):
 *   <tag1> : <value1> <newline>
 *   <tag2> : <value2> <newline>
 *   ...
 * Lines starting with '#' are considered to be comments.
 */


#include "main.h"

#include <iostream>

#include "utils.h"

#include "confio.h"


// Constructor
ConfWriter::ConfWriter(std::ostream &stream)
	: m_out(stream)
{

}

// Writes a comment to the stream
void ConfWriter::putComment(const std::string &text)
{
	m_out << "# " << text << std::endl;
}


// Constructor
ConfReader::ConfReader(std::istream &stream)
	: m_in(stream)
{

}

// Reads the next tag/value pair or returns false
bool ConfReader::next()
{
	if (!m_in.good()) {
		return false;
	}

	// Search for non-comment line
	std::string line;
	do {
		std::getline(m_in, line);
		if (!m_in.good()) {
			return false;
		}
	} while (!line.empty() && line[0] == '#');

	size_t pos = line.find(':');
	if (pos == std::string::npos) {
#ifndef NDEBUG
		std::cerr << "ConfReader: Syntax error at '" << line << "'" << std::endl;
#endif
		next();
	}

	m_tag = Utils::trim(line.substr(0, pos));
	m_value = Utils::trim(line.substr(pos+1));
	return true;
}

// Returns the current tag
std::string ConfReader::tag() const
{
	return m_tag;
}

// Returns the current value as a string
std::string ConfReader::getstr() const
{
	return m_value;
}

// Returns the current value as an integer
int32_t ConfReader::getint() const
{
	int32_t t;
	std::istringstream is(m_value, std::istringstream::in);
	is >> t;
	return t;
}

// Returns the current value as a double
double ConfReader::getdouble() const
{
	double t;
	std::istringstream is(m_value, std::istringstream::in);
	is >> t;
	return t;
}

// Returns the current value as a boolean
bool ConfReader::getbool() const
{
	bool t;
	std::istringstream is(m_value, std::istringstream::in);
	is >> t;
	return t;
}

// Stores the current value as a list of strings
uint32_t ConfReader::getstrs(std::string *values, uint32_t max) const
{
	std::vector<std::string> parts = Utils::split(m_value, ",");
	uint32_t i;
	for (i = 0; i < parts.size() && i < max; i++) {
		values[i] = parts[i];
	}
	return i;
}

// Stores the current value as a list of integers
uint32_t ConfReader::getints(int32_t *values, uint32_t max) const
{
	std::vector<std::string> parts = Utils::split(m_value, ",");
	uint32_t i;
	for (i = 0; i < parts.size() && i < max; i++) {
		std::istringstream is(parts[i], std::istringstream::in);
		is >> values[i];
	}
	return i;
}

// Stores the current value as a list of integers
uint32_t ConfReader::getints(uint32_t *values, uint32_t max) const
{
	std::vector<std::string> parts = Utils::split(m_value, ",");
	uint32_t i;
	for (i = 0; i < parts.size() && i < max; i++) {
		std::istringstream is(parts[i], std::istringstream::in);
		is >> values[i];
	}
	return i;
}

// Stores the current value as a list of doubles
uint32_t ConfReader::getdoubles(double *values, uint32_t max) const
{
	std::vector<std::string> parts = Utils::split(m_value, ",");
	uint32_t i;
	for (i = 0; i < parts.size() && i < max; i++) {
		std::istringstream is(parts[i], std::istringstream::in);
		is >> values[i];
	}
	return i;
}
