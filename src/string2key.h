/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: string2key.h
 * Encryption key calculation from a passphrase
 */


#ifndef STRING2KEY_H_
#define STRING2KEY_H_


#include "main.h"

#include "cryptutils.h"

class PIStream;
class POStream;


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

		PIStream &operator<<(PIStream &in);
		POStream &operator>>(POStream &out);

		String2Key &operator=(const String2Key &other);

	private:
		uint8_t m_usage;
		Spec m_spec;

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
