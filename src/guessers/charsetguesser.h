/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: charsetguessers.h
 * Base class for charset guessers
 */


#ifndef CHARSETGUESSER_H_
#define CHARSETGUESSER_H_


#include "main.h"

#include "guessers.h"


namespace Guessers
{

class CharsetGuesser : public Guesser
{
	public:
		CharsetGuesser(Buffer *buffer);
		~CharsetGuesser();

		virtual void setup(const std::map<std::string, std::string> &options);

	protected:
		virtual bool init();

	protected:
		uint8_t *m_charset;
		uint32_t m_cslength;

		uint32_t m_minlength;
		uint32_t m_maxlength;
};

} // namespace Guessers


#endif // CHARSETGUESSER_H_
