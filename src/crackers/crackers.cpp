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

#include "attack.h"
#include "buffer.h"
#include "string2key.h"

#include "cast5crackers.h"

#include "crackers.h"


namespace Crackers
{

// Constructor
Cracker::Cracker(const Key &key, Buffer *buffer)
	: Thread(), m_key(key), m_buffer(buffer)
{

}

// Main thread loop
void Cracker::run()
{
	if (!init()) {
		std::cerr << "Error initializing cracker!" << std::endl;
		return;
	}

	uint32_t n = 0, numBlocks = 0;
	Memblock blocks[8];

	while (true) {
		numBlocks = m_buffer->taken(8, blocks);

		for (uint32_t i = 0; i < numBlocks; i++) {
			if (blocks[i].length > 0 && check(blocks[i].data, blocks[i].length)) {
				Attack::phraseFound(blocks[i]);
			}
		}

		// Avoid constant status querying
		if (++n > 128) {
			switch (Attack::status()) {
				case Attack::STATUS_SUCCESS:
					return;
				case Attack::STATUS_FAILURE:
					if (blocks[0].length == 0) {
						return;
					}
					break;
				default:
					break;
			}
			n = 0;
		}
	}
}

// Cracker initialization routine
bool Cracker::init()
{
	// The default implementation does nothing
	return true;
}


// Returns a cracker for the given key
Cracker *crackerFor(const Key &key, Buffer *buffer)
{
	const String2Key &s2k = key.string2Key();
	switch (s2k.cipherAlgorithm())
	{
		case CryptUtils::CIPHER_CAST5:
			return cast5CrackerFor(key, buffer);
			break;

		default: break;
	}

	return NULL;
}

} // namespace Crackers
