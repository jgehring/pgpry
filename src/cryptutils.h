/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: cryptutils.h
 * Miscellaneous cryptographic definitions and utilities
 */


#ifndef CRYPTUTILS_H_
#define CRYPTUTILS_H_


#include "main.h"


namespace CryptUtils
{

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
