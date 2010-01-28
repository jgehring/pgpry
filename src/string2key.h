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

		typedef enum {
			CIPHER_UNKOWN = -1,
			CIPHER_CAST5 = 3
		} CipherAlgorithm;

		typedef enum {
			HASH_UNKOWN = -1,
			HASH_MD5 = 1,
			HASH_SHA1 = 2
		} HashAlgorithm;

	public:
		String2Key();
		~String2Key();

		uint8_t usage() const;

		PIStream &operator<<(PIStream &in);
		POStream &operator>>(POStream &out);

	private:
		uint8_t m_usage;
		Spec m_spec;

		HashAlgorithm m_hashAlgorithm;
		uint8_t m_salt[8];
		int32_t m_count;

		CipherAlgorithm m_cipherAlgorithm;
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
