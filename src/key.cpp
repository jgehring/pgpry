/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: key.cpp
 * Represents a PGP key
 */


#include <iostream>
#include <cstring>

#include "packetheader.h"
#include "pistream.h"

#include "key.h"


// Constructor
Key::Key()
	: m_version(255), m_algorithm(PKA_UNKOWN), m_rsa(NULL), m_dsa(NULL), m_expire(0),
	  m_datalen(0), m_data(NULL)
{

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
		throw "Invalid packet type";
	}
	uint32_t headerOff = in.pos();

	// Read public key
	in >> m_version;
	if (m_version != 3 && m_version != 4) {
		throw "Unspported key version";
	}
	in >> m_time;
	if (m_version == 3) {
		in >> m_expire;
	}
	uint8_t tmp;
	in >> tmp; m_algorithm = (Algorithm)tmp;
	if (m_algorithm == PKA_RSA_ENCSIGN) {
		m_rsa = RSA_new();
		in >> m_rsa->n;
		in >> m_rsa->e;
	} else if (m_algorithm == PKA_DSA) {
		m_dsa = DSA_new();
		in >> m_dsa->p;
		in >> m_dsa->q;
		in >> m_dsa->g;
		in >> m_dsa->pub_key;
	} else {
		throw "Unsupprted public-key algorithm";
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
		if (m_algorithm == PKA_RSA_ENCSIGN) {
			in >> m_rsa->d;
			in >> m_rsa->p;
			in >> m_rsa->q;
//			in >> m_rsa->iqmp;
		} else if (m_algorithm == PKA_DSA) {
			in >> m_dsa->priv_key;
		}
	}

	m_locked = (m_s2k.usage() != 0);

	return in;
}
