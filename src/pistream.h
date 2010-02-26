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
 * file: pistream.h
 * PGP input stream
 */


#ifndef PISTREAM_H_
#define PISTREAM_H_


#include "main.h"

#include <istream>

#include <openssl/bn.h>

class PacketHeader;


class PIStream
{
	public:
		PIStream(std::istream &stream);

		uint32_t pos() const;
		bool good() const;
		bool bad() const;
		bool fail() const;

		uint32_t read(char *s, uint32_t n);

		PIStream &operator>>(int8_t &i);
		PIStream &operator>>(uint8_t &i);
		PIStream &operator>>(int16_t &i);
		PIStream &operator>>(uint16_t &i);
		PIStream &operator>>(int32_t &i);
		PIStream &operator>>(uint32_t &i);
		PIStream &operator>>(BIGNUM *&b);

	private:
		void dearmor();

	private:
		std::istream &m_in;
		uint32_t m_read;

		bool m_armored;
		int32_t m_b64count;
		uint32_t m_b64buf;
};

// Inlined functions
inline bool PIStream::good() const
{
	return m_in.good();
}

inline bool PIStream::bad() const
{
	return m_in.bad();
}

inline bool PIStream::fail() const
{
	return m_in.fail();
}

inline PIStream &PIStream::operator>>(uint8_t &i)
{
	return (*this >> reinterpret_cast<int8_t &>(i));
}

inline PIStream &PIStream::operator>>(uint16_t &i)
{
	return (*this >> reinterpret_cast<int16_t &>(i));
}

inline PIStream &PIStream::operator>>(uint32_t &i)
{
	return (*this >> reinterpret_cast<int32_t &>(i));
}


#endif // PISTREAM_H_
