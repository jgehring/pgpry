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
 * file: string2key.cpp
 * Encryption key calculation from a passphrase
 */


#include <iostream>
#include <cstring>

#include "packetheader.h"
#include "pistream.h"

#include "key.h"


// Constructor
String2Key::String2Key()
	: m_spec(SPEC_SIMPLE), m_hashAlgorithm(CryptUtils::HASH_UNKOWN),
	  m_cipherAlgorithm(CryptUtils::CIPHER_UNKOWN), m_iv(NULL)
{

}

// Copy constructor
String2Key::String2Key(const String2Key &other)
{
	*this = other;
}

// Destructor
String2Key::~String2Key()
{
	delete[] m_iv;
}

// Query functions
uint8_t String2Key::usage() const
{
	return m_usage;
}

String2Key::Spec String2Key::spec() const
{
	return m_spec;
}

CryptUtils::HashAlgorithm String2Key::hashAlgorithm() const
{
	return m_hashAlgorithm;
}

const uint8_t *String2Key::salt() const
{
	return m_salt;
}

int32_t String2Key::count() const
{
	return m_count;
}

CryptUtils::CipherAlgorithm String2Key::cipherAlgorithm() const
{
	return m_cipherAlgorithm;
}

const uint8_t *String2Key::ivec() const
{
	return m_iv;
}

// Reads S2K data from a stream
PIStream &String2Key::operator<<(PIStream &in)
{
	// Read usage and spec info
	in >> m_usage;
	if (m_usage == 254 || m_usage == 255) {
		uint8_t tmp;
		in >> tmp; m_cipherAlgorithm = (CryptUtils::CipherAlgorithm)tmp;
		in >> tmp; m_spec = (Spec)tmp;
		in >> tmp; m_hashAlgorithm = (CryptUtils::HashAlgorithm)tmp;
		switch (m_spec) {
			case SPEC_SALTED:
				in.read((char *)m_salt, 8);
				break;

			case SPEC_ITERATED_SALTED: {
				in.read((char *)m_salt, 8);
				uint8_t t;
				in >> t;
				m_count = ((int32_t)16 + (t & 15)) << ((t >> 4) + 6);
				break;
			}

			case SPEC_SIMPLE:
				break;

			default:
				throw "Unknown String2Key spec";
		}
	} else if (m_usage != 0) {
		uint8_t tmp;
		in >> tmp; m_cipherAlgorithm = (CryptUtils::CipherAlgorithm)tmp;
		m_spec = SPEC_SIMPLE;
	}

	// Read cipher initialization vector
	if (m_usage != 0) {
		uint32_t bs = CryptUtils::blockSize(m_cipherAlgorithm);
		m_iv = new uint8_t[bs];
		in.read((char *)m_iv, bs);
	}
	return in;
}

// Assignment operator
String2Key &String2Key::operator=(const String2Key &other)
{
	m_usage = other.m_usage;
	m_spec = other.m_spec;

	m_hashAlgorithm = other.m_hashAlgorithm;
	memcpy(m_salt, other.m_salt, 8);
	m_count = other.m_count;

	m_cipherAlgorithm = other.m_cipherAlgorithm;

	delete[] m_iv;
	uint32_t bs = CryptUtils::blockSize(m_cipherAlgorithm);
	m_iv = new uint8_t[bs];
	memcpy(m_iv, other.m_iv, bs);

	return *this;
}
