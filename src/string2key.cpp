/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
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

// Reads S2K data from a stream 
PIStream &String2Key::operator<<(PIStream &in)
{
	// Read usage and spec info
	in >> m_usage;
	if (m_usage == 254 || m_usage == 255) {
		in >> reinterpret_cast<uint8_t &>(m_cipherAlgorithm);
		in >> reinterpret_cast<uint8_t &>(m_spec);
		in >> reinterpret_cast<uint8_t &>(m_hashAlgorithm);
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
		in >> reinterpret_cast<uint8_t &>(m_cipherAlgorithm);
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
