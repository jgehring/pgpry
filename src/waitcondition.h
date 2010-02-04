/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: waitcondition.h
 * Simple wait condition class using Pthreads
 */


#ifndef WAITCONDITION_H_
#define WAITCONDITION_H_


#include <pthread.h>

#include "mutex.h"


class WaitCondition
{
	public:
		WaitCondition();
		~WaitCondition();

		void wait(Mutex *mutex);
		void wake();
		void wakeAll();

	private:
		pthread_cond_t m_pcond;
};


// Inlined functions
inline void WaitCondition::wait(Mutex *mutex)
{
	pthread_cond_wait(&m_pcond, &mutex->m_pmx);
}

inline void WaitCondition::wake()
{
	pthread_cond_signal(&m_pcond);
}

inline void WaitCondition::wakeAll()
{
	pthread_cond_broadcast(&m_pcond);
}


#endif // WAITCONDITION_H_
