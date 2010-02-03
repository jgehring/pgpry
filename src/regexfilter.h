/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: regexfilter.h
 * Buffer filtering withregular expressions
 */


#ifndef REGEXFILTER_H_
#define REGEXFILTER_H_


#include <vector>

#include "thread.h"

#include "pregex.h"

class Buffer;


class RegexFilter : public Thread
{
	public:
		RegexFilter(Buffer *in, Buffer *out);

		bool readExpressions(const std::string &file);

	protected:
		void run();

	private:
		Buffer *m_in;
		Buffer *m_out;
		std::vector<PRegex> m_posrx;
		std::vector<PRegex> m_negrx;
};


#endif
