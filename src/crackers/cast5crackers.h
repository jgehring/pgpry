/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: cast5crackers.h
 * Crackers for CAST5-encrypted data
 */


#ifndef CAST5CRACKERS_H_
#define CAST5CRACKERS_H_


#include "crackers.h"


namespace Crackers
{

class Cast5MD5Cracker : public Cracker
{
	public:
		Cast5MD5Cracker(const Key &key, Buffer *buffer);

//	protected:
//		bool check(const uint8_t *password, uint32_t length);
};


class Cast5SHA1Cracker : public Cracker
{
	public:
		Cast5SHA1Cracker(const Key &key, Buffer *buffer);
		~Cast5SHA1Cracker();

	protected:
		bool init();
		bool check(const uint8_t *password, uint32_t length);

	private:
		uint8_t *m_keybuf;
		uint8_t m_keydata[20];
		uint8_t m_iv[8];

		uint32_t m_datalen;
		uint8_t *m_in;
		uint8_t *m_out;
};


Cracker *cast5CrackerFor(const Key &key, Buffer *buffer);

} // namespace Crackers;


#endif // CAST5RACKERS_H_
