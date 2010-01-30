/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: utils.h
 * Miscellaneous utility functions
 */


#ifndef UTILS_H_
#define UTILS_H_


#include <string>

#include "main.h"


namespace Utils
{

bool str2int(const std::string &str, int32_t *i);
bool str2int(const std::string &str, uint32_t *i);

} // namespace Utils


#endif // UTILS_H_
