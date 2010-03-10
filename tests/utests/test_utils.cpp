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
 * Unit tests for Utils namespace
 */


#include <cstdlib>
#include <iostream>

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


// Unit test entry point
int test_utils(bool verbose)
{
	struct part_t {
		const char *name;
		void (*function)();
	} parts[] = {
		{ "Utils::str2int()", test_utils_str2int },
		{ "Utils::int2str()", test_utils_int2str },
		{ "Utils::trim()", test_utils_trim }
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
