/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: buffer.h
 * Thread-safe ring buffer for memory blocks
 */


#ifndef BUFFER_H_
#define BUFFER_H_


#include "memblock.h"
#include "mutex.h"
#include "psemaphore.h"


class Buffer
{
	public:
		Buffer(uint32_t size = 2048);
		~Buffer();

		void put(const Memblock &m);
		void take(Memblock *m);

	private:
		Memblock *m_data;
		uint32_t m_size;
		Memblock *m_start, *m_end;

		Mutex m_mutex;
		Semaphore m_used;
		Semaphore m_free;
};


// Inlined functions
inline void Buffer::put(const Memblock &m)
{
	--m_free;
	m_mutex.lock();

	*m_end = m;
	if (++m_end >= m_data + m_size) {
		m_end = m_data;
	}

	m_mutex.unlock();
	++m_used;
}

inline void Buffer::take(Memblock *m)
{
	--m_used;
	m_mutex.lock();

	*m = *m_start;
	if (++m_start >= m_data + m_size) {
		m_start = m_data;
	}

	m_mutex.unlock();
	++m_free;
}


#endif // BUFFER_H_
