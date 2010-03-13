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
 * file: charsetguessers.h
 * Base class for charset guessers
 */


#ifndef CHARSETGUESSER_H_
#define CHARSETGUESSER_H_


#include "guessers.h"


namespace Guessers
{

class CharsetGuesser : public Guesser
{
	public:
		CharsetGuesser(Buffer *buffer);
		~CharsetGuesser();

		virtual void setup(const std::map<std::string, std::string> &options);
		virtual std::vector<std::pair<std::string, std::string> > options() const;

	protected:
		virtual void init();

	protected:
		uint8_t *m_charset;
		uint32_t m_cslength;

		uint32_t m_minlength;
		uint32_t m_maxlength;
};

} // namespace Guessers


#endif // CHARSETGUESSER_H_
