/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
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
	: Thread(), m_in(in), m_out(out)
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
    uint32_t n = 0;
	bool valid;
	while (true) {
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

		// Avoid constant status querying
		if (++n > 128) {
			switch (Attack::status()) {
				case Attack::STATUS_SUCCESS:
					return;
				case Attack::STATUS_FAILURE:
					if (m.length == 0) {
						return;
					}
					break;
				default:
					break;
			}
			n = 0;
		}
	}
}
