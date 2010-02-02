/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: utils.h
 * Miscellaneous utility functions
 */


#ifndef UTILS_H_
#define UTILS_H_


#include <map>
#include <string>

#include "main.h"


namespace Utils
{

uint32_t toBigEndian(uint32_t i);
uint32_t fromBigEndian(uint32_t i);

bool str2int(const std::string &str, int32_t *i);
bool str2int(const std::string &str, uint32_t *i);
std::string int2str(int32_t i);

std::string strprintf(const char *format, ...);

std::string defaultOption(const std::map<std::string, std::string> &options, const std::string name, const std::string &def);
int32_t defaultOption(const std::map<std::string, std::string> &options, const std::string name, int32_t def);

} // namespace Utils


#endif // UTILS_H_
