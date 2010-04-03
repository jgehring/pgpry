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
 * file: prefixsuffixfilter.h
 * Buffer filtering using prefixes and suffixes
 */


#ifndef PREFIXSUFFIXFILTER_H_
#define PREFIXSUFFIXFILTER_H_


#include <vector>
#include <string>

#include "filter.h"


class PrefixSuffixFilter : public Filter
{
	public:
		PrefixSuffixFilter(Buffer *in, Buffer *out);

		void setPrefixes(const std::vector<std::string> &prefixes);
		void setSuffixes(const std::vector<std::string> &suffixes);

	protected:
		void run();

	private:
		std::vector<std::string> m_prefixes;
		std::vector<std::string> m_suffixes;
};


#endif // PREFIXSUFFIXFILTER_H_
