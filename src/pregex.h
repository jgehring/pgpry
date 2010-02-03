/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: pregex.h
 * Simple regular expression class using POSIX regex
 */


#ifndef PREGEX_H_
#define PREGEX_H_


#include "main.h"

#include <string>

#include <regex.h>

#include "memblock.h"


class PRegex
{
	public:
		PRegex(const std::string &pattern);
		PRegex(const PRegex &other);
		~PRegex();

		bool matches(const std::string &str) const;
		bool matches(const Memblock &mblock) const;

		PRegex &operator=(const PRegex &other);

	private:
		std::string errorString(int32_t error);

	private:
		regex_t m_rx;
		std::string m_pattern;
};


// Inlined functions
inline bool PRegex::matches(const std::string &str) const
{
	return (regexec(&m_rx, str.c_str(), 0, NULL, 0) == 0);
}

inline bool PRegex::matches(const Memblock &mblock) const
{
	return (regexec(&m_rx, (const char *)mblock.data, 0, NULL, 0) == 0);
}


#endif // PREGEX_H_
