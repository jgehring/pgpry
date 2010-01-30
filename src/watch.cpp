/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: watch.cpp
 * Small stop watch class
 */


#include <cstdlib>

#include "watch.h"


// Constructor
Watch::Watch()
{
	start();
}

// Starts the stop watch
void Watch::start()
{
	gettimeofday(&m_tv, NULL);
}
