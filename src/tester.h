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
 * file: tester.h
 * Password testing thread
 */


#ifndef TESTER_H_
#define TESTER_H_


#include "cryptutils.h"
#include "key.h"
#include "threads.h"

class Buffer;


class Tester : public SysUtils::Thread
{
	public:
		Tester(const Key &key, Buffer *buffer);
		~Tester();

	protected:
		void run();

	private:
		void init();
		bool check(const Memblock &mblock);

	private:
		Key m_key; // Keep a copy of the key because String2Key is not thread-safe
		Buffer *m_buffer;
		CryptUtils::CipherAlgorithm m_cipher;
		uint32_t m_blockSize;
		uint32_t m_keySize;
		uint32_t m_digestSize;
		uint32_t m_bits;
		uint8_t *m_ivec;
		uint8_t *m_keydata;

		uint32_t m_datalen;
		uint8_t *m_in;
		uint8_t *m_out;
};


#endif // TESTER_H_
