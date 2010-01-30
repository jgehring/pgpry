/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: utils.cpp
 * Miscellaneous utility functions
 */


#include <cerrno>
#include <limits>
#include <cstdlib>
#include <cstring>

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

} // namespace Utils
