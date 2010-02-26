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
 * file: key.cpp
 * Represents a PGP key
 */


#include <iostream>
#include <cstring>

#include "packetheader.h"
#include "pistream.h"
#include "utils.h"

#include "key.h"


// Constructor
Key::Key()
	: m_version(255), m_algorithm(CryptUtils::PKA_UNKOWN), m_rsa(NULL), m_dsa(NULL),
	  m_datalen(0), m_data(NULL), m_expire(0)
{

}

// Copy constructor
Key::Key(const Key &other)
	: m_rsa(NULL), m_dsa(NULL), m_data(NULL)
{
	*this = other;
}

// Destructor
Key::~Key()
{
	if (m_rsa) {
		RSA_free(m_rsa);
	}
	if (m_dsa) {
		DSA_free(m_dsa);
	}
	
	delete[] m_data;
}

// Query functions
bool Key::locked() const
{
	return m_locked;
}

uint32_t Key::dataLength() const
{
	return m_datalen;
}

const uint8_t *Key::data() const
{
	return m_data;
}

const String2Key &Key::string2Key() const
{
	return m_s2k;
}

// Reads a key data from a stream 
PIStream &Key::operator<<(PIStream &in)
{
	// Read packet header
	PacketHeader header;
	in >> header;
	if (!header.valid()) {
		throw "Invalid packet header";
	}
	if (header.type() != PacketHeader::TYPE_SECRET_KEY) {
		throw Utils::strprintf("Invalid packet type %d (not a secret key)", header.type());
	}
	uint32_t headerOff = in.pos();

	// Read public key
	in >> m_version;
	if (m_version != 3 && m_version != 4) {
		throw Utils::strprintf("Unspported key version %d", m_version);
	}
	in >> m_time;
	if (m_version == 3) {
		in >> m_expire;
	}
	uint8_t tmp;
	in >> tmp; m_algorithm = (CryptUtils::PublicKeyAlgorithm)tmp;
	if (m_algorithm == CryptUtils::PKA_RSA_ENCSIGN) {
		m_rsa = RSA_new();
		in >> m_rsa->n;
		in >> m_rsa->e;
	} else if (m_algorithm == CryptUtils::PKA_DSA) {
		m_dsa = DSA_new();
		in >> m_dsa->p;
		in >> m_dsa->q;
		in >> m_dsa->g;
		in >> m_dsa->pub_key;
	} else {
		throw Utils::strprintf("Unsupprted public-key algorithm %d", m_algorithm);
	}

	// Read private key
	in >> m_s2k;
	if (m_s2k.usage() != 0) {
		// Encrypted 
		m_datalen = header.length() - in.pos() + headerOff;
		m_data = new uint8_t[m_datalen];
		if (in.read((char *)m_data, m_datalen) != m_datalen) {
			throw "Premature end of data stream";
		}
	} else {
		// Plaintext
		if (m_algorithm == CryptUtils::PKA_RSA_ENCSIGN) {
			in >> m_rsa->d;
			in >> m_rsa->p;
			in >> m_rsa->q;
			in >> m_rsa->iqmp;
		} else if (m_algorithm == CryptUtils::PKA_DSA) {
			in >> m_dsa->priv_key;
		}
	}

	m_locked = (m_s2k.usage() != 0);

	return in;
}

// Assignment operator
Key &Key::operator=(const Key &other)
{
	m_locked = other.m_locked;
	m_version = other.m_version;

	m_algorithm = other.m_algorithm;

	if (other.m_rsa) {
		m_rsa = RSA_new();
		m_rsa->n = BN_dup(other.m_rsa->n);
		m_rsa->e = BN_dup(other.m_rsa->e);
		if (!other.m_locked) {
			m_rsa->d = BN_dup(other.m_rsa->d);
			m_rsa->p = BN_dup(other.m_rsa->p);
			m_rsa->q = BN_dup(other.m_rsa->q);
			m_rsa->iqmp = BN_dup(other.m_rsa->iqmp);
		}
	} else if (m_rsa) {
		RSA_free(m_rsa);
		m_rsa = NULL;
	}

	if (other.m_dsa) {
		m_dsa = DSA_new();
		m_dsa->p = BN_dup(other.m_dsa->p);
		m_dsa->q = BN_dup(other.m_dsa->q);
		m_dsa->g = BN_dup(other.m_dsa->g);
		m_dsa->pub_key = BN_dup(other.m_dsa->pub_key);
		if (!other.m_locked) {
			m_dsa->priv_key = BN_dup(other.m_dsa->priv_key);
		}
	} else if (m_dsa) {
		DSA_free(m_dsa);
		m_dsa = NULL;
	}

	m_s2k = other.m_s2k;
	m_datalen = other.m_datalen;
	delete[] m_data;
	if (m_s2k.usage() != 0) {
		m_data = new uint8_t[m_datalen];
		memcpy(m_data, other.m_data, m_datalen);
	} else {
		m_data = NULL;
	}

	m_time = other.m_time;
	m_expire = other.m_expire;

	return *this;
}
