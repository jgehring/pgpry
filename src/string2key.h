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
 * file: string2key.h
 * Thread-unsafe encryption key calculation from a passphrase
 */


#ifndef STRING2KEY_H_
#define STRING2KEY_H_


#include "main.h"

#include "cryptutils.h"

class Memblock;
class PIStream;
class POStream;

class S2KGenerator;


class String2Key
{
	public:
		typedef enum {
			SPEC_SIMPLE = 0,
			SPEC_SALTED = 1,
			SPEC_ITERATED_SALTED = 3
		} Spec;

	public:
		String2Key();
		String2Key(const String2Key &other);
		~String2Key();

		uint8_t usage() const;
		Spec spec() const;

		CryptUtils::HashAlgorithm hashAlgorithm() const;
		const uint8_t *salt() const;
		int32_t count() const;

		CryptUtils::CipherAlgorithm cipherAlgorithm() const;
		const uint8_t *ivec() const;

		void generateKey(const Memblock &string, uint8_t *key, uint32_t length) const;

		PIStream &operator<<(PIStream &in);
		POStream &operator>>(POStream &out);

		String2Key &operator=(const String2Key &other);

	private:
		void setupGenerator() const;

	private:
		uint8_t m_usage;
		Spec m_spec;
		mutable S2KGenerator *m_keygen;

		CryptUtils::HashAlgorithm m_hashAlgorithm;
		uint8_t m_salt[8];
		int32_t m_count;

		CryptUtils::CipherAlgorithm m_cipherAlgorithm;
		uint8_t *m_iv;
};

// Convenience operators
inline PIStream &operator>>(PIStream &in, String2Key &s2k)
{
	return (s2k << in);
}

inline POStream &operator<<(POStream &out, String2Key &s2k)
{
	return (s2k >> out);
}


#endif // STRING2KEY_H_
