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
 * file: regexfilter.cpp
 * Buffer filtering with regular expressions
 */


#include <fstream>
#include <iostream>

#include "attack.h"
#include "buffer.h"

#include "regexfilter.h"


// Constructor
RegexFilter::RegexFilter(Buffer *in, Buffer *out)
	: Filter(in, out)
{

}

// Reads a set of regular expressions from the given file
bool RegexFilter::readExpressions(const std::string &file)
{
	std::ifstream in(file.c_str());
	if (in.fail()) {
		std::cerr << "Error: Unable to open file " << file << std::endl;
		return false;
	}

	std::string str;
	while (in.good()) {
		getline(in, str);

		if (str.empty() || str.substr(0, 1) == "#") {
			continue;
		}

		std::vector<SysUtils::Regex> *vptr;
		if (str.substr(0, 2) == "+ ") {
			vptr = &m_posrx;
		} else if (str.substr(0, 2) == "- ") {
			vptr = &m_negrx;
		} else {
			std::cerr << "Warning: Unable to parse regex " << str << std::endl;
			continue;
		}
		try {
			vptr->push_back(str.substr(2));
		} catch (const std::string &errstr) {
			std::cerr << "Warning: Unable to parse regex " << str.substr(2);
			std::cerr << " (" << errstr << ")" << std::endl;
		} catch (...) {
			std::cerr << "Warning: Unable to parse regex " << str.substr(2) << std::endl;
		}
	}

	return true;
}

// Main thread loop
void RegexFilter::run()
{
	Memblock m;
	std::vector<SysUtils::Regex>::const_iterator it;
	bool valid;
	while (!abortFlag()) {
		m_in->take(&m);

		valid = true;
		for (it = m_posrx.begin(); it < m_posrx.end(); ++it) {
			if (!((*it).matches(m))) {
				valid = false;
				break;
			}
		}
		for (it = m_negrx.begin(); it < m_negrx.end(); ++it) {
			if ((*it).matches(m)) {
				valid = false;
				break;
			}
		}

		if (valid) {
			m_out->put(m);
		}
	}
}
