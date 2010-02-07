/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: randomguesser.h
 * Simple random guessing
 */


#ifndef RANDOMGUESSER_H_
#define RANDOMGUESSER_H_


#include "charsetguesser.h"


namespace Guessers
{

class RandomGuesser : public CharsetGuesser
{
	public:
		RandomGuesser(Buffer *buffer);
		~RandomGuesser();

	protected:
		bool init();
		bool guess(Memblock *m);

	private:
		uint32_t m_rblength;
		uint32_t *m_randbuf;
};

} // namespace Guessers


#endif // RANDOMGUESSER_H_
