/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: crackers.h
 * Cracker thread definition and factory
 */


#ifndef CRACKERS_H_
#define CRACKERS_H


#include "key.h"
#include "thread.h"


namespace Crackers
{

class Cracker : public Thread
{
	public:
		Cracker();

	protected:
		virtual void run();
};


Cracker *crackerFor(const Key &key);

} // namespace Crackers;


#endif // CRACKERS_H_
