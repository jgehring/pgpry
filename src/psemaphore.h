/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: psemaphore.h
 * Simple semaphore class using Pthreads
 */


#ifndef PSEMAPHORE_H_
#define PSEMAPHORE_H_


#include <semaphore.h>

#include "main.h"


class Semaphore
{
	public:
		Semaphore(uint32_t n = 0);
		~Semaphore();

		Semaphore &operator--();
		Semaphore &operator++();

	private:
		sem_t m_sem;
};


// Inlined functions
inline Semaphore &Semaphore::operator--()
{
	sem_wait(&m_sem);	
	return *this;
}

inline Semaphore &Semaphore::operator++()
{
	sem_post(&m_sem);	
	return *this;
}


#endif // PSEMAPHORE_H_
