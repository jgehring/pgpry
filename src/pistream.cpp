/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: pistream.cpp
 * PGP input stream
 */


#include <cstring>

#include "config.h"

#include "pistream.h"


// Constructor
PIStream::PIStream(std::istream &stream)
	: m_in(stream), m_read(0), m_armored(false),
	  m_b64count(0), m_b64buf(0)
{
	// Check if the stream is armored. This isn't done
	int32_t b1 = m_in.get();
	int32_t b2 = m_in.peek();
	m_in.unget();
	if (b1 == '-' && b2 == '-') {
		m_armored = true;
		dearmor();
	}
}

// Returns the current stream position
uint32_t PIStream::pos() const
{
	return m_read;
}

// Reads binary data from the (possibly armored) stream
uint32_t PIStream::read(char *s, uint32_t n)
{
	if (!m_armored) {
		m_in.read(s, n);
		m_read += m_in.gcount();
		return m_in.gcount();
	}

	// The Base64 decoding is taken from Qt, again
	uint32_t br = 0;
	while (br < n && m_in.good()) {
		int32_t ch = m_in.get();

		// Decode
		int32_t d;
		if (ch >= 'A' && ch <= 'Z') {
			d = ch - 'A';
		} else if (ch >= 'a' && ch <= 'z') {
			d = ch - 'a' + 26;
		} else if (ch >= '0' && ch <= '9') {
			d = ch - '0' + 52;
		} else if (ch == '+') {
			d = 62;
		} else if (ch == '/') {
			d = 63;
		} else {
			d = -1;
		}

		if (d != -1) {
			m_b64buf = (m_b64buf << 6) | d;
			m_b64count += 6;
			if (m_b64count >= 8) {
				m_b64count -= 8;
				s[br++] = (m_b64buf >> m_b64count);
				m_b64buf &= ((1 << m_b64count) - 1);
			}
		}
	}

	m_read += br;
	return br;
}

// Data extraction operators
PIStream &PIStream::operator>>(int8_t &i)
{
	if (read((char *)&i, 1) != 1) {
		throw "Premature end of data stream";
	}
	return *this;
}

PIStream &PIStream::operator>>(int16_t &i)
{
	// PGP values are big endian
#ifdef WORDS_BIGENDIAN
	if (read((char *)&i, 2) != 2) {
		throw "Premature end of data stream";
	}
#else
	// From Qt
	union {
		int16_t v1;
		char v2[2];
	} t;
	char block[2];
	if (read(block, 2) != 2) {
		throw "Premature end of data stream";
	}
	t.v2[0] = block[1];
	t.v2[1] = block[0];
	i = t.v1;
#endif
	return *this;
}

PIStream &PIStream::operator>>(int32_t &i)
{
	// PGP values are big endian
#ifdef WORDS_BIGENDIAN
	if (read((char *)&i, 4) != 4) {
		throw "Premature end of data stream";
	}
#else
	// From Qt
	union {
		int32_t v1;
		char v2[4];
	} t;
	char block[4];
	if (read(block, 4) != 4) {
		throw "Premature end of data stream";
	}
	t.v2[0] = block[3];
	t.v2[1] = block[2];
	t.v2[2] = block[1]; 
	t.v2[3] = block[0];
	i = t.v1;
#endif
	return *this;
}

PIStream &PIStream::operator>>(BIGNUM *&b)
{
	uint16_t length;
	*this >> length;
	length = (length + 7) / 8; // Length in bits -> length in bytes

	uint8_t *buffer = new uint8_t[length];
	memset(buffer, 0x00, length);
	if (read((char *)buffer, length) != length) {
		throw "Premature end of data stream";
	}
	b = BN_bin2bn(buffer, length, b);
	delete[] buffer;

	return *this;
}

// Strips the ASCII armor headers from a stream
void PIStream::dearmor()
{
	char buffer[255];
	do {
		m_in.getline(buffer, 254);
	} while (m_in.good() && buffer[0] != 0);
}
