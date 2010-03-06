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

#ifdef USE_BLOCK_SHA1
 #include "3rdparty/block-sha1/block-sha1.h"
 #define pgpry_SHA_CTX blk_SHA_CTX
 #define pgpry_SHA1_Init blk_SHA1_Init
 #define pgpry_SHA1_Update blk_SHA1_Update
 #define pgpry_SHA1_Final blk_SHA1_Final
#else
 #include <openssl/sha.h>
 #define pgpry_SHA_CTX SHA_CTX
 #define pgpry_SHA1_Init SHA1_Init
 #define pgpry_SHA1_Update SHA1_Update
 #define pgpry_SHA1_Final SHA1_Final
#endif // USE_BLOCK_SHA1


namespace CryptUtils
{

typedef enum {
	PKA_UNKOWN = 0,
	PKA_RSA_ENCSIGN = 1,
	PKA_DSA = 17
} PublicKeyAlgorithm;

typedef enum {
	CIPHER_UNKOWN = -1,
	CIPHER_CAST5 = 3,
	CIPHER_BLOWFISH = 4,
	CIPHER_AES128 = 7,
	CIPHER_AES192 = 8,
	CIPHER_AES256 = 9
} CipherAlgorithm;

typedef enum {
	HASH_UNKOWN = -1,
	HASH_MD5 = 1,
	HASH_SHA1 = 2
} HashAlgorithm;


uint32_t blockSize(CipherAlgorithm algorithm);
uint32_t keySize(CipherAlgorithm algorithm);
uint32_t digestSize(HashAlgorithm algorithm);

} // namespace CryptUtils


#endif // CRYPTUTILS_H_
