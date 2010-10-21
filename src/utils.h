/*
 * pgpry - PGP private key recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * file: utils.h
 * Miscellaneous utility functions
 */


#ifndef UTILS_H_
#define UTILS_H_


#include <map>
#include <string>
#include <vector>

#include "main.h"


namespace Utils
{

bool str2int(const std::string &str, int32_t *i);
bool str2int(const std::string &str, uint32_t *i);
std::string int2str(int32_t i);

void trim(std::string *str);
std::string trim(const std::string &str);
std::vector<std::string> split(const std::string &str, const std::string &token);

std::string strprintf(const char *format, ...);

std::string defaultOption(const std::map<std::string, std::string> &options, const std::string name, const std::string &def);
int32_t defaultOption(const std::map<std::string, std::string> &options, const std::string name, int32_t def);

} // namespace Utils


#endif // UTILS_H_
