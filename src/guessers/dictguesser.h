/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: dictguesser.h
 * Simple dictionary guesser
 */


#ifndef DICTGUESSER_H_
#define DICTGUESSER_H_


#include <string>
#include <vector>

#include "guessers.h"

#include "memblock.h"


namespace Guessers
{

class DictionaryGuesser : public Guesser
{
	public:
		DictionaryGuesser(Buffer *buffer);

		void setup(const std::map<std::string, std::string> &options);

	protected:
		bool init();
		bool guess(Memblock *m);

	protected:
		std::string m_dictfile;
		uint32_t m_index;
		std::vector<Memblock> m_phrases;
};

} // namespace Guessers


#endif // DICTGUESSER_H_
