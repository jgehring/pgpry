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
 * file: cryptutils.h
 * Miscellaneous cryptographic definitions and utilities
 */


#ifndef CRYPTUTILS_H_
#define CRYPTUTILS_H_


#include "main.h"


namespace CryptUtils
{

typedef enum {
	PKA_UNKOWN = 0,
	PKA_RSA_ENCSIGN = 1,
	PKA_DSA = 17
} PublicKeyAlgorithm;

typedef enum {
	CIPHER_UNKOWN = -1,
	CIPHER_CAST5 = 3
} CipherAlgorithm;

typedef enum {
	HASH_UNKOWN = -1,
	HASH_MD5 = 1,
	HASH_SHA1 = 2
} HashAlgorithm;


uint32_t blockSize(CipherAlgorithm algorithm);
uint32_t keySize(CipherAlgorithm algorithm);

} // namespace CryptUtils


#endif // CRYPTUTILS_H_
