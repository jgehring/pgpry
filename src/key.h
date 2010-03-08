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
 * file: key.h
 * Represents a PGP key
 */


#ifndef KEY_H_
#define KEY_H_


#include "main.h"

#include <openssl/rsa.h>
#include <openssl/dsa.h>

#include "cryptutils.h"
#include "string2key.h"

class PIStream;
class POStream;


class Key
{
	public:
		Key();
		Key(const Key &other);
		~Key();

		bool locked() const;
		uint32_t dataLength() const;
		uint32_t bits() const;
		const uint8_t *data() const;
		const String2Key &string2Key() const;

		PIStream &operator<<(PIStream &in);
		POStream &operator>>(POStream &out);

		Key &operator=(const Key &other);

	private:
		bool m_locked;
		uint8_t m_version;

		CryptUtils::PublicKeyAlgorithm m_algorithm;
		RSA *m_rsa;
		DSA *m_dsa;

		String2Key m_s2k;
		uint32_t m_datalen;
		uint8_t *m_data;

		uint32_t m_time;
		uint16_t m_expire;
};

// Inlined functions
inline uint32_t Key::bits() const
{
	if (m_rsa) {
		return BN_num_bits(m_rsa->n);
	} else if (m_dsa) {
		return BN_num_bits(m_dsa->p);
	}
	return 0;
}

// Convenience operators
inline PIStream &operator>>(PIStream &in, Key &key)
{
	return (key << in);
}

inline POStream &operator<<(POStream &out, Key &key)
{
	return (key >> out);
}


#endif // KEY_H_
