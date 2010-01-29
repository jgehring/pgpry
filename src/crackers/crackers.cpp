/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: crackers.cpp
 * Cracker thread definition and factory
 */


#include <cassert>
#include <cstring>
#include <iostream>

#include "string2key.h"

#include "cast5crackers.h"

#include "crackers.h"


namespace Crackers
{

// Constructor
Cracker::Cracker(const Key &key)
	: Thread(), m_key(key)
{

}

// Main thread loop
void Cracker::run()
{
	init();

	// TODO
}

// Cracker initialization routine
void Cracker::init()
{
	// The default implementation does nothing
}


// Returns a cracker for the given key
Cracker *crackerFor(const Key &key)
{
	const String2Key &s2k = key.string2Key();
	switch (s2k.cipherAlgorithm())
	{
		case CryptUtils::CIPHER_CAST5:
			return cast5CrackerFor(key);
			break;

		default: break;
	}

	return NULL;
}

} // namespace Crackers
