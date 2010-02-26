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
 * file: packetheader.h
 * Represents a PGP packet header
 */


#ifndef PACKETHEADER_H_
#define PACKETHEADER_H_


#include "main.h"

class PIStream;
class POStream;


class PacketHeader
{
	public:
		typedef enum {
			FORMAT_UNKOWN = -1,
			FORMAT_OLD,
			FORMAT_NEW
		} Format;

		typedef enum {
			TYPE_UNKOWN = -1,
			TYPE_SECRET_KEY = 5,
			TYPE_PUBLIC_KEY = 6
		} Type;

	public:
		PacketHeader();

		bool valid() const;
		Format format() const;
		Type type() const;
		int32_t length() const;

		PIStream &operator<<(PIStream &in);
		POStream &operator>>(POStream &out);

	private:
		Format m_format;
		Type m_type;
		int32_t m_length;
};


// Convenience operators
inline PIStream &operator>>(PIStream &in, PacketHeader &header)
{
	return (header << in);
}

inline POStream &operator<<(POStream &out, PacketHeader &header)
{
	return (header >> out);
}


#endif // PACKETHEADER_H_
