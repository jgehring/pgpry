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


#ifndef SHA1CRACKER_H_
#define SHA1CRACKER_H_


#include "crackers.h"


namespace Crackers
{

class SHA1Cracker : public Cracker
{
	public:
		SHA1Cracker(const Key &key, Buffer *buffer);
		~SHA1Cracker();

	protected:
		void init();
		bool check(const uint8_t *password, uint32_t length);

	private:
		uint8_t *m_keybuf;
		uint8_t *m_keydata;
		uint32_t m_numKeyHashes;

		uint32_t m_datalen;
		uint8_t *m_in;
		uint8_t *m_out;
};

} // namespace Crackers


#endif // SHA1CRACKER_H_
