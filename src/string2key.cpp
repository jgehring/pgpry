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
 * file: string2key.cpp
 * Encryption key calculation from a passphrase
 */


#include <cassert>
#include <cstring>
#include <iostream>

#include <openssl/md5.h>

#include "memblock.h"
#include "packetheader.h"
#include "pistream.h"
#include "utils.h"

#include "key.h"


#define KEYBUFFER_LENGTH 8192


// Key generator base class
class S2KGenerator
{
	public:
		virtual ~S2KGenerator() { }
		virtual void genkey(const Memblock &string, uint8_t *key, uint32_t length) const = 0;
};

// "Simple" generators
class S2KSimpleSHA1Generator : public S2KGenerator
{
	public:
		void genkey(const Memblock &string, uint8_t *key, uint32_t length) const
		{
			pgpry_SHA_CTX ctx;
			uint32_t numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;

			for (uint32_t i = 0; i < numHashes; i++) {
				pgpry_SHA1_Init(&ctx);
				for (uint32_t j = 0; j < i; j++) {
					pgpry_SHA1_Update(&ctx, "\0", 1);
				}
				pgpry_SHA1_Update(&ctx, string.data, string.length);
				pgpry_SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
			}
		}
};

class S2KSimpleMD5Generator : public S2KGenerator
{
	public:
		void genkey(const Memblock &string, uint8_t *key, uint32_t length) const
		{
			MD5_CTX ctx;
			uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;

			for (uint32_t i = 0; i < numHashes; i++) {
				MD5_Init(&ctx);
				for (uint32_t j = 0; j < i; j++) {
					MD5_Update(&ctx, "\0", 1);
				}
				MD5_Update(&ctx, string.data, string.length);
				MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
			}
		}
};

// "Salted" generators
class S2KSaltedGenerator : public S2KGenerator
{
	public:
		S2KSaltedGenerator(const uint8_t salt[8])
		{
			memcpy(m_salt, salt, 8);
		}

	protected:
		uint8_t m_salt[8];
};

class S2KSaltedSHA1Generator : public S2KSaltedGenerator
{
	public:
		S2KSaltedSHA1Generator(const uint8_t salt[8]) : S2KSaltedGenerator(salt) { }

		void genkey(const Memblock &string, uint8_t *key, uint32_t length) const
		{
			pgpry_SHA_CTX ctx;
			uint32_t numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;

			for (uint32_t i = 0; i < numHashes; i++) {
				pgpry_SHA1_Init(&ctx);
				for (uint32_t j = 0; j < i; j++) {
					pgpry_SHA1_Update(&ctx, "\0", 1);
				}
				pgpry_SHA1_Update(&ctx, m_salt, 8);
				pgpry_SHA1_Update(&ctx, string.data, string.length);
				pgpry_SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
			}
		}
};

class S2KSaltedMD5Generator : public S2KSaltedGenerator
{
	public:
		S2KSaltedMD5Generator(const uint8_t salt[8]) : S2KSaltedGenerator(salt) { }

		void genkey(const Memblock &string, uint8_t *key, uint32_t length) const
		{
			MD5_CTX ctx;
			uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;

			for (uint32_t i = 0; i < numHashes; i++) {
				MD5_Init(&ctx);
				for (uint32_t j = 0; j < i; j++) {
					MD5_Update(&ctx, "\0", 1);
				}
				MD5_Update(&ctx, m_salt, 8);
				MD5_Update(&ctx, string.data, string.length);
				MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
			}
		}
};

// "Iterated Salted" generators
class S2KItSaltedGenerator : public S2KSaltedGenerator
{
	public:
		S2KItSaltedGenerator(const uint8_t salt[8], uint32_t count)
			: S2KSaltedGenerator(salt), m_count(count) { }

	protected:
		uint32_t m_count;
};

class S2KItSaltedSHA1Generator : public S2KItSaltedGenerator
{
	public:
		S2KItSaltedSHA1Generator(const uint8_t salt[8], uint32_t count)
			: S2KItSaltedGenerator(salt, count)
		{
			m_keybuf = new uint8_t[KEYBUFFER_LENGTH];
			memcpy(m_keybuf, m_salt, 8);
		}
		~S2KItSaltedSHA1Generator() { delete[] m_keybuf; }

		void genkey(const Memblock &string, uint8_t *key, uint32_t length) const
		{
			pgpry_SHA_CTX ctx;
			uint32_t numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;

			// TODO: This is not very efficient with multiple hashes
			for (uint32_t i = 0; i < numHashes; i++) {
				pgpry_SHA1_Init(&ctx);
				for (uint32_t j = 0; j < i; j++) {
					pgpry_SHA1_Update(&ctx, "\0", 1);
				}

				// Find multiplicator
				int32_t tl = string.length + 8;
				int32_t mul = 1;
				while (mul < tl && ((64 * mul) % tl)) {
					++mul;
				}

				// Try to feed the hash function with 64-byte blocks
				const int32_t bs = mul * 64;
				assert(bs <= KEYBUFFER_LENGTH);
				uint8_t *bptr = m_keybuf + tl;
				int32_t n = bs / tl;
				memcpy(m_keybuf + 8, string.data, string.length);
				while (n-- > 1) {
					memcpy(bptr, m_keybuf, tl);
					bptr += tl;
				}
				n = m_count / bs;
				while (n-- > 0) {
					pgpry_SHA1_Update(&ctx, m_keybuf, bs);
				}
				pgpry_SHA1_Update(&ctx, m_keybuf, m_count % bs);

				pgpry_SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
			}
		}

	private:
		mutable uint8_t *m_keybuf;
};

class S2KItSaltedMD5Generator : public S2KItSaltedGenerator
{
	public:
		S2KItSaltedMD5Generator(const uint8_t salt[8], uint32_t count)
			: S2KItSaltedGenerator(salt, count)
		{
			m_keybuf = new uint8_t[KEYBUFFER_LENGTH];
			memcpy(m_keybuf, m_salt, 8);
		}
		~S2KItSaltedMD5Generator() { delete[] m_keybuf; }

		void genkey(const Memblock &string, uint8_t *key, uint32_t length) const
		{
			MD5_CTX ctx;
			uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;

			// TODO: This is not very efficient with multiple hashes
			for (uint32_t i = 0; i < numHashes; i++) {
				MD5_Init(&ctx);
				for (uint32_t j = 0; j < i; j++) {
					MD5_Update(&ctx, "\0", 1);
				}

				// Find multiplicator
				int32_t tl = string.length + 8;
				int32_t mul = 1;
				while (mul < tl && ((64 * mul) % tl)) {
					++mul;
				}

				// Try to feed the hash function with 64-byte blocks
				const int32_t bs = mul * 64;
				assert(bs <= KEYBUFFER_LENGTH);
				uint8_t *bptr = m_keybuf + tl;
				int32_t n = bs / tl;
				memcpy(m_keybuf + 8, string.data, string.length);
				while (n-- > 1) {
					memcpy(bptr, m_keybuf, tl);
					bptr += tl;
				}
				n = m_count / bs;
				while (n-- > 0) {
					MD5_Update(&ctx, m_keybuf, bs);
				}
				MD5_Update(&ctx, m_keybuf, m_count % bs);

				MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
			}
		}

	private:
		mutable uint8_t *m_keybuf;
};


// Constructor
String2Key::String2Key()
	: m_spec(SPEC_SIMPLE), m_keygen(NULL), m_hashAlgorithm(CryptUtils::HASH_UNKOWN),
	  m_cipherAlgorithm(CryptUtils::CIPHER_UNKOWN), m_iv(NULL)
{
	memset(m_salt, 0x00, 8);
}

// Copy constructor
String2Key::String2Key(const String2Key &other)
{
	*this = other;
}

// Destructor
String2Key::~String2Key()
{
	delete m_keygen;
	delete[] m_iv;
}

// Query functions
uint8_t String2Key::usage() const
{
	return m_usage;
}

String2Key::Spec String2Key::spec() const
{
	return m_spec;
}

CryptUtils::HashAlgorithm String2Key::hashAlgorithm() const
{
	return m_hashAlgorithm;
}

const uint8_t *String2Key::salt() const
{
	return m_salt;
}

int32_t String2Key::count() const
{
	return m_count;
}

CryptUtils::CipherAlgorithm String2Key::cipherAlgorithm() const
{
	return m_cipherAlgorithm;
}

const uint8_t *String2Key::ivec() const
{
	return m_iv;
}

// Generates a key out of the given string
void String2Key::generateKey(const Memblock &string, uint8_t *key, uint32_t length) const
{
	if (m_keygen == NULL) {
		setupGenerator();
	}
	m_keygen->genkey(string, key, length);
}

// Reads S2K data from a stream
PIStream &String2Key::operator<<(PIStream &in)
{
	// Read usage and spec info
	in >> m_usage;
	if (m_usage == 254 || m_usage == 255) {
		uint8_t tmp;
		in >> tmp; m_cipherAlgorithm = (CryptUtils::CipherAlgorithm)tmp;
		in >> tmp; m_spec = (Spec)tmp;
		in >> tmp; m_hashAlgorithm = (CryptUtils::HashAlgorithm)tmp;
		switch (m_spec) {
			case SPEC_SALTED:
				in.read((char *)m_salt, 8);
				break;

			case SPEC_ITERATED_SALTED: {
				in.read((char *)m_salt, 8);
				uint8_t t;
				in >> t;
				m_count = ((int32_t)16 + (t & 15)) << ((t >> 4) + 6);
			}
			break;

			case SPEC_SIMPLE:
				break;

			default:
				throw "Unknown String2Key spec";
		}
	} else if (m_usage != 0) {
		uint8_t tmp;
		in >> tmp; m_cipherAlgorithm = (CryptUtils::CipherAlgorithm)tmp;
		m_spec = SPEC_SIMPLE;
	}

	// Read cipher initialization vector
	if (m_usage != 0) {
		uint32_t bs = CryptUtils::blockSize(m_cipherAlgorithm);
		m_iv = new uint8_t[bs];
		in.read((char *)m_iv, bs);
	}
	return in;
}

// Assignment operator
String2Key &String2Key::operator=(const String2Key &other)
{
	m_usage = other.m_usage;
	m_spec = other.m_spec;

	m_hashAlgorithm = other.m_hashAlgorithm;
	memcpy(m_salt, other.m_salt, 8);
	m_count = other.m_count;

	m_cipherAlgorithm = other.m_cipherAlgorithm;

	delete[] m_iv;
	uint32_t bs = CryptUtils::blockSize(m_cipherAlgorithm);
	m_iv = new uint8_t[bs];
	memcpy(m_iv, other.m_iv, bs);

	return *this;
}

// Sets up the key generator
void String2Key::setupGenerator() const
{
	delete m_keygen;
	m_keygen = NULL;

	switch (m_spec)
	{
		case SPEC_ITERATED_SALTED: {
			switch (m_hashAlgorithm) {
				case CryptUtils::HASH_MD5:
					m_keygen = new S2KItSaltedMD5Generator(m_salt, m_count);
					break;
				case CryptUtils::HASH_SHA1:
					m_keygen = new S2KItSaltedSHA1Generator(m_salt, m_count);
					break;
				default: break;
			}
		}
		break;

		case SPEC_SALTED: {
			switch (m_hashAlgorithm) {
				case CryptUtils::HASH_MD5:
					m_keygen = new S2KSaltedMD5Generator(m_salt);
					break;
				case CryptUtils::HASH_SHA1:
					m_keygen = new S2KSaltedSHA1Generator(m_salt);
					break;
				default: break;
			}
		}
		break;

		case SPEC_SIMPLE: {
			switch (m_hashAlgorithm) {
				case CryptUtils::HASH_MD5:
					m_keygen = new S2KSimpleMD5Generator();
					break;
				case CryptUtils::HASH_SHA1:
					m_keygen = new S2KSimpleSHA1Generator();
					break;
				default: break;
			}
		}
		break;

		default:
			throw Utils::strprintf("Unkown S2K specification (%d)", m_spec);
	}

	if (m_keygen == NULL)
	{
		throw Utils::strprintf("Unkown hash algorithm (%d)", m_hashAlgorithm);
	}
}
