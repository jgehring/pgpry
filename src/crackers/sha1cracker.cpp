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
 * file: sha1cracker.h
 * A cracker specialized to SHA1-Hashing
 */


#include <cassert>
#include <cstring>
#include <iostream>

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/cast.h>

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

#include "utils.h"

#include "sha1cracker.h"


#define KEYBUFFER_LENGTH 8192


namespace Crackers
{

// Constructor
SHA1Cracker::SHA1Cracker(const Key &key, Buffer *buffer)
	: Cracker(key, buffer), m_keybuf(NULL), m_keydata(NULL),
	  m_in(NULL), m_out(NULL)
{

}

// Destructor
SHA1Cracker::~SHA1Cracker()
{
	delete[] m_keybuf;
	delete[] m_keydata;
	delete[] m_in;
	delete[] m_out;
}

// Cracker initialization
void SHA1Cracker::init()
{
	Cracker::init();

	const String2Key &s2k = m_key.string2Key();
	assert(s2k.hashAlgorithm() == CryptUtils::HASH_SHA1);

	m_keybuf = new uint8_t[KEYBUFFER_LENGTH];
	if (s2k.spec() != String2Key::SPEC_SIMPLE) {
		memcpy(m_keybuf, s2k.salt(), 8);
	}

	switch (m_cipher) {
		case CryptUtils::CIPHER_CAST5:
		case CryptUtils::CIPHER_AES128:
		case CryptUtils::CIPHER_AES192:
		case CryptUtils::CIPHER_AES256:
			break;

		default:
			throw Utils::strprintf("Unsupported cipher algorithm: %d", s2k.cipherAlgorithm());
	}

	// How many hashes are needed for the key
	m_numKeyHashes = 1;
	while (m_numKeyHashes * SHA_DIGEST_LENGTH < m_keySize) {
		++m_numKeyHashes;
	}
	m_keydata = new uint8_t[m_numKeyHashes * SHA_DIGEST_LENGTH];

	m_datalen = m_key.dataLength();
	m_in = new uint8_t[m_datalen];
	memcpy(m_in, m_key.data(), m_datalen);
	m_out = new uint8_t[m_datalen];
}

// Checks if a password is valid
bool SHA1Cracker::check(const uint8_t *password, uint32_t length)
{
	const String2Key &s2k = m_key.string2Key();
	uint32_t count = s2k.count();

	pgpry_SHA_CTX ctx;

	for (uint32_t i = 0; i < m_numKeyHashes; i++) {
		pgpry_SHA1_Init(&ctx);
		for (uint32_t j = 0; j < i; j++) {
			pgpry_SHA1_Update(&ctx, "\0", 1);
		}

		switch (s2k.spec()) {
			case String2Key::SPEC_ITERATED_SALTED: {
				// Find multiplicator
				int32_t tl = length + 8;
				int32_t mul = 1;
				while (mul < tl && ((64 * mul) % tl)) {
					++mul;
				}
				// Try to feed the hash function with 64-byte blocks
				const int32_t bs = mul * 64;
				assert(bs <= KEYBUFFER_LENGTH);
				uint8_t *bptr = m_keybuf + tl;
				int32_t n = bs / tl;
				memcpy(m_keybuf + 8, password, length);
				while (n-- > 1) {
					memcpy(bptr, m_keybuf, tl);
					bptr += tl;
				}
				n = count / bs;
				while (n-- > 0) {
					pgpry_SHA1_Update(&ctx, m_keybuf, bs);
				}
				pgpry_SHA1_Update(&ctx, m_keybuf, count % bs);
				break;
			}

			case String2Key::SPEC_SALTED:
				pgpry_SHA1_Update(&ctx, s2k.salt(), 8);
				pgpry_SHA1_Update(&ctx, password, length);
				break;

			default:
				pgpry_SHA1_Update(&ctx, password, length);
				break;
		}

		pgpry_SHA1_Final(m_keydata + (i * SHA_DIGEST_LENGTH), &ctx);
	}

	int32_t tmp = 0;

	// Decrypt first data block in order to check the first two bits of
	// the MPI. If they are correct, there's a good chance that the
	// password is correct, too.
#if 1
	memcpy(m_ivec, s2k.ivec(), m_blockSize);
	switch (m_cipher) {
		case CryptUtils::CIPHER_CAST5: {
			CAST_KEY ck;
			CAST_set_key(&ck, SHA_DIGEST_LENGTH, m_keydata);
			CAST_cfb64_encrypt(m_in, m_out, CAST_BLOCK, &ck, m_ivec, &tmp, CAST_DECRYPT);
		}
		break;
		case CryptUtils::CIPHER_AES128:
		case CryptUtils::CIPHER_AES192:
		case CryptUtils::CIPHER_AES256: {
			AES_KEY ck;
			AES_set_encrypt_key(m_keydata, m_keySize * 8, &ck);
			AES_cfb128_encrypt(m_in, m_out, AES_BLOCK_SIZE, &ck, m_ivec, &tmp, AES_DECRYPT);
		}
		break;

		default:
			break;
	}

	uint32_t num_bits = ((m_out[0] << 8) | m_out[1]);
	if (num_bits > m_key.bits()) {
		return false;
	}
#endif

	// Decrypt all data
	memcpy(m_ivec, s2k.ivec(), m_blockSize);
	tmp = 0;
	switch (m_cipher) {
		case CryptUtils::CIPHER_CAST5: {
			CAST_KEY ck;
			CAST_set_key(&ck, SHA_DIGEST_LENGTH, m_keydata);
			CAST_cfb64_encrypt(m_in, m_out, m_datalen, &ck, m_ivec, &tmp, CAST_DECRYPT);
		}
		break;
		case CryptUtils::CIPHER_AES128:
		case CryptUtils::CIPHER_AES192:
		case CryptUtils::CIPHER_AES256: {
			AES_KEY ck;
			AES_set_encrypt_key(m_keydata, m_keySize * 8, &ck);
			AES_cfb128_encrypt(m_in, m_out, m_datalen, &ck, m_ivec, &tmp, AES_DECRYPT);
		}
		break;

		default:
			break;
	}

	// Verify
	bool checksumOk = false;
	switch (s2k.usage()) {
		case 254: {
			pgpry_SHA1_Init(&ctx);
			pgpry_SHA1_Update(&ctx, m_out, m_datalen - 20);
			pgpry_SHA1_Final(m_keydata, &ctx);
			if (memcmp(m_keydata, m_out + m_datalen - 20, 20) == 0) {
				checksumOk = true;
			}
		} break;

		case 0:
		case 255: {
			uint16_t sum = 0;
			for (uint32_t i = 0; i < m_datalen - 2; i++) {
				sum += m_out[i];
			}
			if (sum == ((m_out[m_datalen - 2] << 8) | m_out[m_datalen - 1])) {
				checksumOk = true;
			}
		} break;

		default:
			break;
	}

	// If the checksum is ok, try to parse the first MPI of the private key
	if (checksumOk) {
		BIGNUM *b = NULL;
		uint32_t blen = (((m_out[0] << 8) | m_out[1]) + 7) / 8;
		if (blen < m_datalen && BN_bin2bn(m_out + 2, blen, b) != NULL) {
			BN_free(b);
			return true;
		}
	}

	return false;
}

} // namespace Crackers;
