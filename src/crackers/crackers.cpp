/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: crackers.cpp
 * Cracker thread definition and factory
 */


#include <cassert>
#include <iostream>

#include "crackers.h"


namespace Crackers
{

// Constructor
Cracker::Cracker()
	: Thread()
{

}

// Main thread loop
void Cracker::run()
{
	// TODO
}


// Returns a cracker suited for the given key
Cracker *crackerFor(const Key &key)
{
	return new Cracker();
}

} // namespace Crackers
