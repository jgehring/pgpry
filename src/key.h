/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: key.h
 * Represents a PGP key
 */


#ifndef KEY_H_
#define KEY_H_


#include "main.h"

#include <openssl/rsa.h>
#include <openssl/dsa.h>

#include "string2key.h"

class PIStream;
class POStream;


class Key
{
	public:
		typedef enum {
			PKA_UNKOWN = 0,
			PKA_RSA_ENCSIGN = 1,
			PKA_DSA = 17
		} Algorithm;

	public:
		Key();
		~Key();

		bool locked() const;
		uint8_t *encryptedData(uint8_t **data, uint32_t *len) const;

		PIStream &operator<<(PIStream &in);
		POStream &operator>>(POStream &out);

	private:
		bool m_locked;
		uint8_t m_version;

		Algorithm m_algorithm;
		RSA *m_rsa;
		DSA *m_dsa;

		String2Key m_s2k;
		uint32_t m_datalen;
		uint8_t *m_data;

		uint32_t m_time;
		uint16_t m_expire;
};

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
