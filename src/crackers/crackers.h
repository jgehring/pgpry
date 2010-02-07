/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: crackers.h
 * Cracker thread definition and factory
 */


#ifndef CRACKERS_H_
#define CRACKERS_H_


#include "key.h"
#include "threads.h"

class Buffer;


namespace Crackers
{

class Cracker : public SysUtils::Thread
{
	public:
		Cracker(const Key &key, Buffer *buffer);
		virtual ~Cracker() { }

	protected:
		void run();

		virtual bool init();
		virtual bool check(const uint8_t *password, uint32_t length) = 0;

	protected:
		Key m_key;

	private:
		Buffer *m_buffer;
};


Cracker *crackerFor(const Key &key, Buffer *buffer);

} // namespace Crackers


#endif // CRACKERS_H_
