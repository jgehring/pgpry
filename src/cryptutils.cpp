/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: cryptutils.cpp
 * Miscellaneous cryptographic definitions and utilities
 */


#include "cryptutils.h"


namespace CryptUtils
{

// Returns the block size (in bytes) of a given cipher
uint32_t blockSize(CipherAlgorithm algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return 8;

		default: break;
	}

	return 0;
}

// Returns the key size (in bytes) of a given cipher
uint32_t keySize(CipherAlgorithm algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return 16;

		default: break;
	}

	return 0;
}

} // namespace CryptUtils
