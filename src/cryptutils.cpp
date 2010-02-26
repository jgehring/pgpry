/*
 * pgpry - PGP private key recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
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
