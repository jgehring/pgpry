/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
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
		bool init();
		bool check(const uint8_t *password, uint32_t length);

	private:
		uint8_t *m_keybuf;
		uint8_t *m_keydata;

		uint32_t m_datalen;
		uint8_t *m_in;
		uint8_t *m_out;
};

} // namespace Crackers


#endif // SHA1CRACKER_H_
