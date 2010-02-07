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
#include "threads.h"


class Buffer
{
	public:
		Buffer(uint32_t size = 8192);
		~Buffer();

		uint32_t size();

		void put(const Memblock &m);
		uint32_t putn(uint32_t n, const Memblock *m);
		void take(Memblock *m);
		uint32_t taken(uint32_t n, Memblock *m);

	private:
		Memblock *m_data;
		uint32_t m_size;
		Memblock *m_start, *m_end;

		SysUtils::Mutex m_mutex;
		SysUtils::Semaphore m_used;
		SysUtils::Semaphore m_free;
};


// Inlined functions
inline uint32_t Buffer::size()
{
	uint32_t t;
	m_mutex.lock();
	t = m_size;
	m_mutex.unlock();
	return t;
}

inline void Buffer::put(const Memblock &m)
{
	m_free.acquire(1);
	m_mutex.lock();

	*m_end = m;
	if (++m_end >= m_data + m_size) {
		m_end = m_data;
	}

	m_mutex.unlock();
	m_used.release(1);
}

inline uint32_t Buffer::putn(uint32_t n, const Memblock *m)
{
	m_free.acquire(n);
	m_mutex.lock();

	for (uint32_t i = 0; i < n; i++) {
		*m_end = m[i];
		if (++m_end >= m_data + m_size) {
			m_end = m_data;
		}
	}

	m_mutex.unlock();
	m_used.release(n);
	return n;
}

inline void Buffer::take(Memblock *m)
{
	m_used.acquire(1);
	m_mutex.lock();

	*m = *m_start;
	if (++m_start >= m_data + m_size) {
		m_start = m_data;
	}

	m_mutex.unlock();
	m_free.release(1);
}

inline uint32_t Buffer::taken(uint32_t n, Memblock *m)
{
	m_used.acquire(n);
	m_mutex.lock();

	for (uint32_t i = 0; i < n; i++) {
		m[i] = *m_start;
		if (++m_start >= m_data + m_size) {
			m_start = m_data;
		}
	}

	m_mutex.unlock();
	m_free.release(n);
	return n;
}


#endif // BUFFER_H_
