/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: mutex.cpp
 * Simple mutex class using Pthreads
 */


#include "mutex.h"


// Constructor
Mutex::Mutex()
{
	pthread_mutex_init(&m_pmx, NULL);
}

// Destructor
Mutex::~Mutex()
{
	pthread_mutex_destroy(&m_pmx);
}
