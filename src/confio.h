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
 * file: confio.h
 * Configuration file reading and writing
 */


#ifndef CONFIO_H_
#define CONFIO_H_


#include "main.h"

#include <istream>
#include <ostream>
#include <sstream>


class ConfWriter
{
	public:
		ConfWriter(std::ostream &stream);

		template <typename T>
		void put(const std::string &tag, T value) {
			m_out << tag << ": " << value << std::endl;
		}
		void putComment(const std::string &text);

	private:
		std::ostream &m_out;
};


class ConfReader
{
	public:
		ConfReader(std::istream &stream);

		bool next();
		std::string tag() const;
		template <typename T>
		T get() {
			T tmp;
			std::istringstream is(m_value, std::istringstream::in);
			is >> tmp;
			return tmp;
		}

	private:
		std::istream &m_in;
		std::string m_tag;
		std::string m_value;
};


#endif // CONFIO_H_
