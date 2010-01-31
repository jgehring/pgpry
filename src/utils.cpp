/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: utils.cpp
 * Miscellaneous utility functions
 */


#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <sstream>

#include "utils.h"


namespace Utils
{

// Wrapper for strtol()
template<typename T>
static bool tstr2int(const std::string &str, T *i)
{
	char *end;
	long val = strtol(str.c_str(), &end, 0);

	if (errno == ERANGE || str.c_str() == end
		|| val > std::numeric_limits<int32_t>::max()
	    || val < std::numeric_limits<int32_t>::min()) {
		return false;
	}

	*i = (T)val;
	return true;
}

// Wrapper for strtol()
bool str2int(const std::string &str, int32_t *i)
{
	return tstr2int<int32_t>(str, i);
}

// Wrapper for strtol()
bool str2int(const std::string &str, uint32_t *i)
{
	return tstr2int<uint32_t>(str, i);
}

// sprintf for std::string
std::string strprintf(const char *format, ...)
{
	va_list vl;
	va_start(vl, format);

	std::ostringstream os;

	const char *ptr = format-1;
	while (*(++ptr) != '\0') {
		if (*ptr != '%') {
			os << *ptr;
			continue;
		}

		++ptr;

		// Only a subset of format specifiers is supported
		switch (*ptr) {
			case 'd':
			case 'i':
				os << va_arg(vl, int);
				break;

			case 'c':
				os << (unsigned char)va_arg(vl, int);
				break;

			case 'e':
			case 'E':
			case 'f':
			case 'F':
			case 'g':
			case 'G':
				os << va_arg(vl, double);
				break;

			case 's':
				os << va_arg(vl, const char *);
				break;

			case '%':
				os << '%';
				break;

			default:
#ifndef NDEBUG
				std::cerr << "Error in strprintf(): unknown format specifier " << *ptr << std::endl;
				exit(1);
#endif
				break;
		}
	}

	va_end(vl);
	return os.str();
}

} // namespace Utils
