/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: buffer.cpp
 * Thread-safe ring buffer for memory blocks
 */


#include "buffer.h"


// Constructor
Buffer::Buffer(uint32_t size)
	: m_used(0), m_free(size), m_size(size)
{
	m_data = new Memblock[size];
	m_start = m_end = m_data;
}

// Destructor
Buffer::~Buffer()
{
	delete[] m_data;
}
