/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: guessers.h
 * Guesser thread definition and factory
 */


#ifndef GUESSERS_H_
#define GUESSERS_H_


#include <map>
#include <string>

#include "thread.h"

class Buffer;
class Memblock;


namespace Guessers
{

class Guesser : public Thread
{
	public:
		Guesser(Buffer *buffer);
		virtual ~Guesser() { }

		virtual void setup(const std::map<std::string, std::string> &options);

	protected:
		void run();

		virtual bool init();
		virtual bool guess(Memblock *m) = 0;

	private:
		Buffer *m_buffer;
};


Guesser *guesser(const std::string &name, Buffer *buffer);

} // namespace Guessers


#endif // GUESSERS_H_
