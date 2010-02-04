/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: waitcondition.cpp
 * Simple wait condition class using Pthreads
 */


#include "waitcondition.h"


// Constructor
WaitCondition::WaitCondition()
{
	pthread_cond_init(&m_pcond, NULL);
}

// Destructor
WaitCondition::~WaitCondition()
{
	pthread_cond_destroy(&m_pcond);
}
