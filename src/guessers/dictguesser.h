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
 * file: dictguesser.h
 * Simple dictionary guesser
 */


#ifndef DICTGUESSER_H_
#define DICTGUESSER_H_


#include <string>
#include <vector>

#include "guessers.h"

#include "memblock.h"


namespace Guessers
{

class DictionaryGuesser : public Guesser
{
	public:
		DictionaryGuesser(Buffer *buffer);

		void setup(const std::map<std::string, std::string> &options);
		std::vector<std::pair<std::string, std::string> > options() const;

	protected:
		void init();
		bool guess(Memblock *m);

	protected:
		std::string m_dictfile;
		uint32_t m_index;
		std::vector<Memblock> m_phrases;
};

} // namespace Guessers


#endif // DICTGUESSER_H_
