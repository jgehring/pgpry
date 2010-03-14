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
 * file: utest/test_utils.cpp
 * Unit tests for the Utils namespace
 */


#include <cstdlib>
#include <iostream>
#include <sstream>
#include <vector>

#include "utils.h"


// Tests for Utils::str2int()
static void test_utils_str2int()
{
	struct inout_t {
		std::string in;
		bool ret;
		int32_t out;
	} inout[] = {
		{ "", false, 0 },
		{ "0", true, 0 },
		{ "12.34", true, 12 },
		{ "789ab", true, 789 },
		{ "-12", true, -12 },
		{ "nede", false, 0 }
	};

	for (unsigned int i = 0; i < sizeof(inout) / sizeof(inout_t); i++) {
		int32_t out;
		bool ret = Utils::str2int(inout[i].in, &out);
		if (ret != inout[i].ret) {
			throw Utils::strprintf("Invalid return value for input '%s' (expected %d, got %d)", inout[i].in.c_str(), inout[i].ret, ret);
		}
		if (ret && out != inout[i].out) {
			throw Utils::strprintf("Invalid result for input '%s' (expected %d, got %d)", inout[i].in.c_str(), inout[i].out, out);
		}
	}
}

// Tests for Utils::int2str()
static void test_utils_int2str()
{
	struct inout_t {
		int32_t in;
		std::string out;
	} inout[] = {
		{ 0, "0" },
		{ 123, "123" },
		{ -1024, "-1024" }
	};

	for (unsigned int i = 0; i < sizeof(inout) / sizeof(inout_t); i++) {
		std::string out = Utils::int2str(inout[i].in);
		if (out != inout[i].out) {
			throw Utils::strprintf("Invalid result for input '%d' (expected '%s', got '%s')", inout[i].in, inout[i].out.c_str(), out.c_str());
		}
	}
}

// Tests for Utils::trim()
static void test_utils_trim()
{
	struct inout_t {
		std::string in;
		std::string out;
	} inout[] = {
		{ "", "" },
		{ "0", "0" },
		{ " ab", "ab" },
		{ "ab  ", "ab" },
		{ " ab ", "ab" },
		{ "\tab  \n", "ab" }
	};

	for (unsigned int i = 0; i < sizeof(inout) / sizeof(inout_t); i++) {
		std::string out = Utils::trim(inout[i].in);
		if (out != inout[i].out) {
			throw Utils::strprintf("Invalid return value for input '%s' (expected '%s', got '%s')", inout[i].in.c_str(), inout[i].out.c_str(), out.c_str());
		}
	}
}

// Tests for Utils::split()
static void test_utils_split()
{
	struct inout_t {
		std::string in;
		std::string token;
		std::vector<std::string> out;
	} inout[] = {
		{ "", "", std::vector<std::string>() },
		{ "", "token", std::vector<std::string>() },
		{ "1,2,3", ",", std::vector<std::string>() }, // "1,2,3"
		{ "1,2,3", "token", std::vector<std::string>() }, // "1,2,3"
		{ "abc1abc2abc3abc", "abc", std::vector<std::string>() }, // ",1,2,3,"
		{ "1abc2abc3abc ", "abc", std::vector<std::string>() }, // "1,2,3, "
		{ "defdef", "def", std::vector<std::string>() }, // ",,"
		{ "defdef", "", std::vector<std::string>() } // ",,"
	};
	inout[2].out.push_back("1");
	inout[2].out.push_back("2");
	inout[2].out.push_back("3");
	inout[3].out.push_back("1,2,3");
	inout[4].out.push_back("");
	inout[4].out.push_back("1");
	inout[4].out.push_back("2");
	inout[4].out.push_back("3");
	inout[4].out.push_back("");
	inout[5].out.push_back("1");
	inout[5].out.push_back("2");
	inout[5].out.push_back("3");
	inout[5].out.push_back(" ");
	inout[6].out.push_back("");
	inout[6].out.push_back("");
	inout[6].out.push_back("");
	inout[7].out.push_back("d");
	inout[7].out.push_back("e");
	inout[7].out.push_back("f");
	inout[7].out.push_back("d");
	inout[7].out.push_back("e");
	inout[7].out.push_back("f");

	for (unsigned int i = 0; i < sizeof(inout) / sizeof(inout_t); i++) {
		std::vector<std::string> out = Utils::split(inout[i].in, inout[i].token);
		if (out != inout[i].out) {
			std::ostringstream os;
			os << "Invalid return value for input '" << inout[i].in << "', '" << inout[i].token << "' ";
			os << "(expected '";
			for (unsigned int j = 0; j < inout[i].out.size(); j++) {
				os << inout[i].out[j];
				if (j != inout[i].out.size()-1) {
					os << ",";
				}
			}
			os << "', got '";
			for (unsigned int j = 0; j < out.size(); j++) {
				os << out[j];
				if (j != out.size()-1) {
					os << ",";
				}
			}
			os << "')";
			throw os.str();
		}
	}
}


// Unit test entry point
int test_utils(bool verbose)
{
	struct part_t {
		const char *name;
		void (*function)();
	} parts[] = {
		{ "Utils::str2int()", test_utils_str2int },
		{ "Utils::int2str()", test_utils_int2str },
		{ "Utils::trim()", test_utils_trim },
		{ "Utils::split()", test_utils_split }
	};

	for (unsigned int i = 0; i < sizeof(parts) / sizeof(part_t); i++) {
		if (verbose) {
			std::cout << "Testing " << parts[i].name << "... ";
		}
		try {
			(*parts[i].function)();
			if (verbose) {
				std::cout << "ok" << std::endl;
			}
		} catch (const std::string &err) {
			if (verbose) {
				std::cout << "failed: " << err << std::endl;
			} else {
				std::cerr << "Testing " << parts[i].name << " failed: " << err << std::endl;
			}
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
