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
 * file: sysutils/threads.h
 * Utility and wrapper classes for POSIX threads
 */


#ifndef THREADS_H_
#define THREADS_H_


#include "main.h"

#include <pthread.h>
#include <semaphore.h>


namespace SysUtils
{

class Thread
{
	public:
		Thread();
		virtual ~Thread() { }

		void start();
		void wait();

	protected:
		virtual void run() = 0;

	private:
		static void *main(void *obj);

	private:
		pthread_t m_pth;
		volatile bool m_running;
};


class Mutex
{
	friend class WaitCondition;

	public:
		Mutex();
		~Mutex();

		inline void lock() {
			pthread_mutex_lock(&m_pmx);
		}
		inline void unlock() {
			pthread_mutex_unlock(&m_pmx);
		}

	private:
		pthread_mutex_t m_pmx;
};


class WaitCondition
{
	public:
		WaitCondition();
		~WaitCondition();

		inline void wait(Mutex *mutex) {
			pthread_cond_wait(&m_pcond, &mutex->m_pmx);
		}
		inline void wake() {
			pthread_cond_signal(&m_pcond);
		}
		inline void wakeAll() {
			pthread_cond_broadcast(&m_pcond);
		}

	private:
		pthread_cond_t m_pcond;
};


class Semaphore
{
	public:
		Semaphore(uint32_t n = 0);
		~Semaphore();

		inline void acquire(int32_t n = 1) {
			pthread_mutex_lock(&m_mutex);
			while (n > m_avail) {
				pthread_cond_wait(&m_cond, &m_mutex);
			}
			m_avail -= n;
			pthread_mutex_unlock(&m_mutex);
		}
		inline void release(int32_t n = 1) {
			pthread_mutex_lock(&m_mutex);
			m_avail += n;
			pthread_cond_broadcast(&m_cond);
			pthread_mutex_unlock(&m_mutex);
		}

	private:
		int32_t m_avail;
		pthread_mutex_t m_mutex;
		pthread_cond_t m_cond;
};

} // namespace SysUtils


#endif // THREADS_H_
