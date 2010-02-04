/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: mutex.h
 * Simple mutex class using Pthreads
 */


#ifndef MUTEX_H_
#define MUTEX_H_


#include <pthread.h>


class Mutex
{
	friend class WaitCondition;

	public:
		Mutex();
		~Mutex();

		void lock();
		void unlock();

	private:
		pthread_mutex_t m_pmx;
};


// Inlined functions
inline void Mutex::lock()
{
	pthread_mutex_lock(&m_pmx);
}

inline void Mutex::unlock()
{
	pthread_mutex_unlock(&m_pmx);
}


#endif // MUTEX_H_
