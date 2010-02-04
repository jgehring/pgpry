/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: psemaphore.cpp
 * Simple semaphore class using Pthreads
 */


#include "psemaphore.h"


// Constructor
Semaphore::Semaphore(uint32_t n)
	: m_avail(n)
{
	pthread_mutex_init(&m_mutex, NULL);
	pthread_cond_init(&m_cond, NULL);
}

// Destructor
Semaphore::~Semaphore()
{
	pthread_mutex_destroy(&m_mutex);
	pthread_cond_destroy(&m_cond);
}
