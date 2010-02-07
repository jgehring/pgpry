/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: cast5crackers.cpp
 * Crackers for CAST5-encrypted data
 */


#include <cstring>
#include <iostream>

#include <openssl/cast.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "cast5crackers.h"


namespace Crackers
{

// Constructor
Cast5Cracker::Cast5Cracker(const Key &key, Buffer *buffer)
	: Cracker(key, buffer), m_keybuf(NULL), m_keydata(NULL),
	  m_in(NULL), m_out(NULL)
{

}

// Destructor
Cast5Cracker::~Cast5Cracker()
{
	delete[] m_keybuf;
	delete[] m_keydata;
	delete[] m_in;
	delete[] m_out;
}

// Cracker initialization
bool Cast5Cracker::init()
{
	const String2Key &s2k = m_key.string2Key();

	if (s2k.spec() != String2Key::SPEC_SIMPLE) {
		m_keybuf = new uint8_t[s2k.count()*2];
		memcpy(m_keybuf, s2k.salt(), 8);
	} else {
		m_keybuf = new uint8_t[65535];
	}

	switch (s2k.hashAlgorithm()) {
		case CryptUtils::HASH_MD5:
			m_keylen = MD5_DIGEST_LENGTH;
			break;
		case CryptUtils::HASH_SHA1:
			m_keylen = SHA_DIGEST_LENGTH;
			break;
		default:
			return false;
	}
	m_keydata = new uint8_t[m_keylen];

	m_datalen = m_key.dataLength();
	m_in = new uint8_t[m_datalen];
	memcpy(m_in, m_key.data(), m_datalen);
	m_out = new uint8_t[m_datalen];

	return true;
}

// Checks if a password is valid
bool Cast5Cracker::check(const uint8_t *password, uint32_t length)
{
	const String2Key &s2k = m_key.string2Key();
	uint32_t count = s2k.count();

	// Prepare key buffer
	uint32_t kblen = 0;
	switch (s2k.spec()) {
		case String2Key::SPEC_ITERATED_SALTED: {
			int32_t tl = length + 8;
			memcpy(m_keybuf + 8, password, length);
			uint8_t *tptr = m_keybuf + tl;
			uint32_t c = tl;
			while (c < count-tl) {
				memcpy(tptr, m_keybuf, tl);
				tptr += tl;
				c += tl;
			}
			if (c < count) {
				memcpy(tptr, m_keybuf, count-c);
				c = count;
			}
			kblen = c;
			break;
		}

		case String2Key::SPEC_SALTED:
			kblen = length + 8;
			memcpy(m_keybuf + 8, password, length);
			break;

		default:
			kblen = length;
			memcpy(m_keybuf, password, length);
			break;
	}

	// Apply hash algorithm
	switch (s2k.hashAlgorithm()) {
		case CryptUtils::HASH_MD5:
			MD5(m_keybuf, kblen, m_keydata);
			break;
		case CryptUtils::HASH_SHA1:
			SHA1(m_keybuf, kblen, m_keydata);
			break;
		default:
			return false;
	}

	// Setup the decryption parameters
	CAST_KEY ck;
	CAST_set_key(&ck, m_keylen, m_keydata);

	memcpy(m_iv, s2k.ivec(), 8);
	int32_t tmp = 0;

#if 0
	// Decrypt first block in order to check the first two bits of the MPI.
	// If they are correct, there's a good chance that the password is right.
	CAST_cfb64_encrypt(m_in, m_out, 16, &ck, m_iv, &tmp, CAST_DECRYPT);
	int32_t num_bits = (m_out[0] << 8 | m_out[1]);
	if (num_bits != 1019) { // TODO
		return false;
	}
#endif

	// Decrypt all data
	tmp = 0;
	memcpy(m_iv, s2k.ivec(), 8);
	CAST_cfb64_encrypt(m_in, m_out, m_datalen, &ck, m_iv, &tmp, CAST_DECRYPT);

	// Verify
	if (s2k.usage() == 254) {
		unsigned char checksum[20];
		SHA1(m_out, m_datalen - 20, checksum);
		if (memcmp(checksum, m_out + m_datalen - 20, 20) == 0) {
//			std::cout << num_bits << std::endl;
			return true;
		}
	}

	return false;
}


// Returns a cracker for the given key
Cracker *cast5CrackerFor(const Key &key, Buffer *buffer)
{
	const String2Key &s2k = key.string2Key();
	switch (s2k.hashAlgorithm()) {
		case CryptUtils::HASH_MD5:
		case CryptUtils::HASH_SHA1:
			return new Cast5Cracker(key, buffer);

		default: break;
	}

	return NULL;
}

} // namespace Crackers;
