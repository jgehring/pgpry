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
#include "thread.h"


namespace Crackers
{

class Cracker : public Thread
{
	public:
		Cracker(const Key &key);

	protected:
		void run();

		virtual void init();
		virtual bool check(const uint8_t *password, uint32_t length) = 0;

	protected:
		Key m_key;
};


Cracker *crackerFor(const Key &key);

} // namespace Crackers;


#endif // CRACKERS_H_
