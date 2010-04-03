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
 * file: prefixsuffixfilter.cpp
 * Buffer filtering using prefixes and suffixes
 */


#include <iostream>

#include "attack.h"
#include "buffer.h"

#include "prefixsuffixfilter.h"


// Constructor
PrefixSuffixFilter::PrefixSuffixFilter(Buffer *in, Buffer *out)
	: Filter(in, out)
{

}

// Sets the prefixes
void PrefixSuffixFilter::setPrefixes(const std::vector<std::string> &prefixes)
{
	m_prefixes = prefixes;
}

// Sets the suffixes
void PrefixSuffixFilter::setSuffixes(const std::vector<std::string> &suffixes)
{
	m_suffixes = suffixes;
}

// Main thread loop
void PrefixSuffixFilter::run()
{
	Memblock m, buffer, buffer2;

	// Pre-calculate memory blocks
	Memblock *prefixBlocks = (m_prefixes.empty() ? NULL : new Memblock[m_prefixes.size()]);
	for (uint32_t i = 0; i < m_prefixes.size(); i++) {
		prefixBlocks[i] = m_prefixes[i].c_str();
	}
	Memblock *suffixBlocks = (m_suffixes.empty() ? NULL : new Memblock[m_suffixes.size()]);
	for (uint32_t i = 0; i < m_suffixes.size(); i++) {
		suffixBlocks[i] = m_suffixes[i].c_str();
	}

	if (m_suffixes.empty()) {
		while (!abortFlag()) {
			m_in->take(&m);
			for (uint32_t i = 0; i < m_prefixes.size(); i++) {
				buffer = m;
				buffer += prefixBlocks[i];
				m_out->put(buffer);
			}
		}
	} else if (m_prefixes.empty()) {
		while (!abortFlag()) {
			m_in->take(&m);
			for (uint32_t i = 0; i < m_suffixes.size(); i++) {
				buffer = m;
				buffer += suffixBlocks[i];
				m_out->put(buffer);
			}
		}
	} else {
		while (!abortFlag()) {
			m_in->take(&m);
			for (uint32_t i = 0; i < m_prefixes.size(); i++) {
				buffer = m;
				buffer += prefixBlocks[i];
				for (uint32_t j = 0; j < m_suffixes.size(); j++) {
					buffer2 = buffer;
					buffer2 += suffixBlocks[j];
					m_out->put(buffer2);
				}
			}
		}
	}

	delete[] prefixBlocks;
	delete[] suffixBlocks;
}
