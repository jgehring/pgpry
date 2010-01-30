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
{
	sem_init(&m_sem, 0, n);
}

// Destructor
Semaphore::~Semaphore()
{
	sem_destroy(&m_sem);
}
