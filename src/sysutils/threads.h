/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
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
