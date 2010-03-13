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
 * file: incguesser.h
 * Simple incremental guessing
 */


#ifndef INCGUESSER_H_
#define INCGUESSER_H_


#include "charsetguesser.h"


namespace Guessers
{

class IncrementalGuesser : public CharsetGuesser
{
	public:
		IncrementalGuesser(Buffer *buffer);
		~IncrementalGuesser();

		void saveState(ConfWriter *writer) const;
		void loadState(ConfReader *reader);

	protected:
		void init();
		bool guess(Memblock *m);

	private:
		uint32_t m_length;
		uint32_t *m_indexes;
		bool m_hasNext;
};

} // namespace Guessers


#endif // INCGUESSER_H_
