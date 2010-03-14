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
		uint32_t capacity();

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
	t = m_used.available();
	m_mutex.unlock();
	return t;
}

inline uint32_t Buffer::capacity()
{
	return m_size;
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
	n = m_used.maxAcquire(n);
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
