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
 * file: crackers.h
 * Cracker thread definition and factory
 */


#ifndef CRACKERS_H_
#define CRACKERS_H_


#include "key.h"
#include "threads.h"
#include "cryptutils.h"

class Buffer;


namespace Crackers
{

class Cracker : public SysUtils::Thread
{
	public:
		Cracker(const Key &key, Buffer *buffer);
		virtual ~Cracker();

	protected:
		void run();

		virtual bool init();
		virtual bool check(const uint8_t *password, uint32_t length) = 0;

	protected:
		Key m_key;
		CryptUtils::CipherAlgorithm m_cipher;
		uint8_t *m_ivec;

	private:
		Buffer *m_buffer;
};


Cracker *crackerFor(const Key &key, Buffer *buffer);

} // namespace Crackers


#endif // CRACKERS_H_
