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
 * file: tester.cpp
 * Password testing thread
 */


#include <iostream>

#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/bn.h>
#include <openssl/cast.h>

#include "attack.h"
#include "buffer.h"
#include "utils.h"

#include "tester.h"


// Minimum number of bits when checking the first BN
#define MIN_BN_BITS 64


// Constructor
Tester::Tester(const Key &key, Buffer *buffer)
	: Thread(), m_key(key), m_buffer(buffer), m_ivec(NULL), m_keydata(NULL),
	  m_in(NULL), m_out(NULL)
{

}

// Destructor
Tester::~Tester()
{
	delete[] m_ivec;
	delete[] m_keydata;
	delete[] m_in;
	delete[] m_out;
}

// Main thread loop
void Tester::run()
{
	try {
		init();
	} catch (const std::string &str) {
		Attack::error(str);
		return;
	} catch (const char *str) {
		Attack::error(str);
		return;
	}

	uint32_t numBlocks = 0;
	Memblock blocks[8];

	while (!abortFlag()) {
		numBlocks = m_buffer->taken(8, blocks);

		for (uint32_t i = 0; i < numBlocks; i++) {
			if (blocks[i].length > 0 && check(blocks[i])) {
				Attack::phraseFound(blocks[i]);
			}
		}
	}
}

// Initializes the tester
void Tester::init()
{
	// Let's cache a few values
	m_cipher = m_key.string2Key().cipherAlgorithm();
	m_blockSize = CryptUtils::blockSize(m_cipher);
	m_keySize = CryptUtils::keySize(m_cipher);
	m_digestSize = CryptUtils::digestSize(m_key.string2Key().hashAlgorithm());
	m_bits = m_key.bits();

	// m_ivec is a temporary initialization vector cache
	uint32_t bs = CryptUtils::blockSize(m_cipher);
	m_ivec = new uint8_t[bs];

	m_datalen = m_key.dataLength();
	m_in = new uint8_t[m_datalen];
	memcpy(m_in, m_key.data(), m_datalen);
	m_out = new uint8_t[m_datalen];

	// Check if given cipher is supported
	switch (m_cipher) {
		case CryptUtils::CIPHER_CAST5:
		case CryptUtils::CIPHER_BLOWFISH:
		case CryptUtils::CIPHER_AES128:
		case CryptUtils::CIPHER_AES192:
		case CryptUtils::CIPHER_AES256:
			break;

		default:
			throw Utils::strprintf("Unsupported cipher algorithm: %d", m_cipher);
	}

	// Pre-allocate string2key buffer
	m_keydata = new uint8_t[m_digestSize * ((m_keySize + m_digestSize - 1) / m_digestSize)];

	// Errors will be catched here, so try the key generation
	m_key.string2Key().generateKey(Memblock("test"), m_keydata, m_keySize);
}

// Checks if the given password is valid
bool Tester::check(const Memblock &mblock)
{
	const String2Key &s2k = m_key.string2Key();
	int32_t tmp = 0;

	// Generate key from password
	s2k.generateKey(mblock, m_keydata, m_keySize);

	// Decrypt first data block in order to check the first two bits of
	// the MPI. If they are correct, there's a good chance that the
	// password is correct, too.
#if 1
	memcpy(m_ivec, s2k.ivec(), m_blockSize);
	switch (m_cipher) {
		case CryptUtils::CIPHER_CAST5: {
			CAST_KEY ck;
			CAST_set_key(&ck, m_keySize, m_keydata);
			CAST_cfb64_encrypt(m_in, m_out, CAST_BLOCK, &ck, m_ivec, &tmp, CAST_DECRYPT);
		}
		break;
		case CryptUtils::CIPHER_BLOWFISH: {
			BF_KEY ck;
			BF_set_key(&ck, m_keySize, m_keydata);
			BF_cfb64_encrypt(m_in, m_out, BF_BLOCK, &ck, m_ivec, &tmp, BF_DECRYPT);
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
	if (num_bits < MIN_BN_BITS || num_bits > m_bits) {
		return false;
	}
#endif

	// Decrypt all data
	memcpy(m_ivec, s2k.ivec(), m_blockSize);
	tmp = 0;
	switch (m_cipher) {
		case CryptUtils::CIPHER_CAST5: {
			CAST_KEY ck;
			CAST_set_key(&ck, m_keySize, m_keydata);
			CAST_cfb64_encrypt(m_in, m_out, m_datalen, &ck, m_ivec, &tmp, CAST_DECRYPT);
		}
		break;
		case CryptUtils::CIPHER_BLOWFISH: {
			BF_KEY ck;
			BF_set_key(&ck, m_keySize, m_keydata);
			BF_cfb64_encrypt(m_in, m_out, m_datalen, &ck, m_ivec, &tmp, BF_DECRYPT);
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
			uint8_t checksum[SHA_DIGEST_LENGTH];
			pgpry_SHA_CTX ctx;
			pgpry_SHA1_Init(&ctx);
			pgpry_SHA1_Update(&ctx, m_out, m_datalen - SHA_DIGEST_LENGTH);
			pgpry_SHA1_Final(checksum, &ctx);
			if (memcmp(checksum, m_out + m_datalen - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) == 0) {
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
		uint32_t blen = (num_bits + 7) / 8;
		if (blen < m_datalen && ((b = BN_bin2bn(m_out + 2, blen, NULL)) != NULL)) {
			BN_free(b);
			return true;
		}
	}

	return false;
}
