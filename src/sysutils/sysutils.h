/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: sysutils/sysutils.h
 * Various system utilities and wrapper classes
 */


#ifndef SYSUTILS_H_
#define SYSUTILS_H_


#include "main.h"

#include <string>

#include <regex.h>
#include <sys/time.h>

#include "memblock.h"


namespace SysUtils
{

class Regex
{
	public:
		Regex(const std::string &pattern);
		Regex(const Regex &other);
		~Regex();

		bool matches(const std::string &str) const {
			return (regexec(&m_rx, str.c_str(), 0, NULL, 0) == 0);
		}
		bool matches(const Memblock &mblock) const {
			return (regexec(&m_rx, (const char *)mblock.data, 0, NULL, 0) == 0);
		}

		Regex &operator=(const Regex &other);

	private:
		std::string errorString(int32_t error);

	private:
		regex_t m_rx;
		std::string m_pattern;
};


class Watch
{
	public:
		Watch();

		void start();
		uint32_t elapsed() const {
			timeval c;
			gettimeofday(&c, NULL);	
 			return (c.tv_sec - m_tv.tv_sec) * 1000 + (c.tv_usec - m_tv.tv_usec) / 1000;
 		}

	private:
		timeval m_tv;
};

} // namespace SysUtils


#endif // SYSUTILS_H_
