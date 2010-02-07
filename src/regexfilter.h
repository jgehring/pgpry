/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: regexfilter.h
 * Buffer filtering with regular expressions
 */


#ifndef REGEXFILTER_H_
#define REGEXFILTER_H_


#include <vector>

#include "sysutils.h"
#include "threads.h"


class Buffer;


class RegexFilter : public SysUtils::Thread
{
	public:
		RegexFilter(Buffer *in, Buffer *out);

		bool readExpressions(const std::string &file);

	protected:
		void run();

	private:
		Buffer *m_in;
		Buffer *m_out;
		std::vector<SysUtils::Regex> m_posrx;
		std::vector<SysUtils::Regex> m_negrx;
};


#endif
