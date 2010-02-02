/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: memblock.h
 * Simple data block class
 *
 * All functions make sure that there's always a trailing null byte. This way,
 * other classes are able to treat the data pointer like a string.
 */


#ifndef MEMBLOCK_H_
#define MEMBLOCK_H_


#include <cstring>

#include "main.h"


class Memblock
{
	public:
		Memblock();
		Memblock(const char *string);
		Memblock(const Memblock &other);
		~Memblock();

		void resize(uint32_t n);

		Memblock &operator=(const Memblock &other);

	public: // By intention
		uint8_t *data;
		uint32_t length;

	private:
		uint32_t m_alloced;
};


// Inlined functions
inline Memblock::Memblock()
	: data(NULL), length(0), m_alloced(0)
{

}

inline Memblock::Memblock(const char *string)
{
	length = strlen(string);
	data = new uint8_t[length+1];
	data[length] = 0x00;
	memcpy(data, string, length);
	m_alloced = length+1;
}

inline Memblock::Memblock(const Memblock &other)
	: data(NULL), length(0), m_alloced(0)
{
	*this = other;
}

inline Memblock::~Memblock()
{
	delete[] data;
}

inline void Memblock::resize(uint32_t n)
{
	if (data == NULL) {
		data = new uint8_t[n+1];
		data[n] = 0x00;
		m_alloced = n+1;
		length = n;
		return;
	}

	if (m_alloced < n+1) {
		uint8_t *tmp = data;
		data = new uint8_t[n+1];
		data[n] = 0x00;
		m_alloced = n+1;
		memcpy(data, tmp, length+1);
		delete[] tmp;
	}
	length = n;
}

inline Memblock &Memblock::operator=(const Memblock &other)
{
	if (this == &other) {
		return *this;
	}

	if (other.data == NULL) {
		delete[] data;
		data = NULL;
		length = 0;
		m_alloced = 0;
		return *this;
	}

	if (m_alloced < other.length+1) {
		delete[] data;
		data = new uint8_t[other.length+1];
		data[other.length] = 0x00;
		m_alloced = other.length+1;
	}

	memcpy(data, other.data, other.length);
	length = other.length;
	return *this;
}


#endif
