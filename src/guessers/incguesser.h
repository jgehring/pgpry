/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: incguesser.h
 * Simple incremental guessing
 */


#ifndef INCGUESSER_H_
#define INCGUESSER_H_


#include "charsetguesser.h"


namespace Guessers
{

class IncrementalGuesser : public CharsetGuesser
{
	public:
		IncrementalGuesser(Buffer *buffer);
		~IncrementalGuesser();

	protected:
		bool init();
		bool guess(Memblock *m);

	private:
		uint32_t m_length;
		uint32_t *m_indexes;
};

} // namespace Guessers


#endif // INCGUESSER_H_
