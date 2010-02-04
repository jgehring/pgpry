/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: psemaphore.h
 * Simple semaphore class using Pthreads
 */


#ifndef PSEMAPHORE_H_
#define PSEMAPHORE_H_


#include <pthread.h>
#include <semaphore.h>

#include "main.h"


class Semaphore
{
	public:
		Semaphore(uint32_t n = 0);
		~Semaphore();

		void acquire(int32_t n = 1);
		void release(int32_t n = 1);

	private:
		int32_t m_avail;
		pthread_mutex_t m_mutex;
		pthread_cond_t m_cond;
};


// Inlined functions
inline void Semaphore::acquire(int32_t n)
{
	pthread_mutex_lock(&m_mutex);
	while (n > m_avail) {
		pthread_cond_wait(&m_cond, &m_mutex);
	}
	m_avail -= n;
	pthread_mutex_unlock(&m_mutex);
}

inline void Semaphore::release(int32_t n)
{
	pthread_mutex_lock(&m_mutex);
	m_avail += n;
	pthread_cond_broadcast(&m_cond);
	pthread_mutex_unlock(&m_mutex);
}


#endif // PSEMAPHORE_H_
