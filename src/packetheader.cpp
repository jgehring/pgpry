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
 * file: packetheader.cpp
 * Represents a PGP packet header
 */


#include "pistream.h"

#include "packetheader.h"


// Constructor
PacketHeader::PacketHeader()
	: m_format(FORMAT_UNKOWN), m_type(TYPE_UNKOWN), m_length(-1)
{

}

// Query functions
bool PacketHeader::valid() const
{
	return (m_length > 0);
}

PacketHeader::Format PacketHeader::format() const
{
	return m_format;
}

PacketHeader::Type PacketHeader::type() const
{
	return m_type;
}

int32_t PacketHeader::length() const
{
	return m_length;
}

// Reads the header from a stream
PIStream &PacketHeader::operator<<(PIStream &in)
{
	uint8_t byte;
	in >> byte;
	if (byte & 0x40) {
		m_format = FORMAT_NEW;
		m_type = (Type)(byte & 0x3F);

		// TODO: This is currently UNTESTED!
		in >> byte;
		if (byte < 192) {
			m_length = byte;
		} else if (byte < 224) {
			m_length = (byte - 192) << 8;
			in >> byte;
			m_length += (int32_t)byte + 192;
		} else if (byte == 255) {
			in >> m_length;
		} else {
			m_length = -1;
		}
	} else {
		m_format = FORMAT_OLD;
		m_type = (Type)((byte & 0x3C) >> 2);

		switch (byte & 0x03) {
			case 0: {
				uint8_t t;
				in >> t;
				m_length = (int32_t)t;
				break;
			}
			case 1: {
				uint16_t t;
				in >> t;
				m_length = (int32_t)t;
				break;
			}
			case 2: {
				in >> m_length;
				break;
			}
			case 3:
			default: {
				// This is currently unsupported
				m_length = -1;
				break;
			}
		}
	}

	return in;
}
