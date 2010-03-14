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
 * file: utest/test_memblock.cpp
 * Unit tests for the Memblock class
 */


#include <cstdlib>
#include <cstring>
#include <iostream>

#include "memblock.h"
#include "utils.h"


// Tests for Memblock::Memblock() and overloaded versions
static void test_memblock_constructors()
{
	struct inout_t {
		const char *in;
		const char *data;
		unsigned int length;
	} inout[] = {
		{ "", "", 0 },
		{ "\0\0", "", 0 },
		{ "hello", "hello", 5 },
		{ "hel\0lo", "hel", 3 }
	};

	for (unsigned int i = 0; i < sizeof(inout) / sizeof(inout_t); i++) {
		Memblock m(inout[i].in);
		if (memcmp(m.data, inout[i].data, m.length)) {
			throw Utils::strprintf("Invalid data for input '%s' (expected '%s', got '%s')", inout[i].in, inout[i].data, m.data);
		}
		if (m.length != inout[i].length) {
			throw Utils::strprintf("Invalid length for input '%s' (expected '%d', got '%d')", inout[i].in, inout[i].length, m.length);
		}

		Memblock m2(m);
		if (memcmp(m2.data, inout[i].data, m2.length)) {
			throw Utils::strprintf("Invalid data for input '%s' (expected '%s', got '%s')", inout[i].in, inout[i].data, m2.data);
		}
		if (m2.length != inout[i].length) {
			throw Utils::strprintf("Invalid length for input '%s' (expected '%d', got '%d')", inout[i].in, inout[i].length, m2.length);
		}
	}
}

// Tests for Memblock::operator=()
static void test_memblock_assign()
{
	struct inout_t {
		const char *in;
		const char *data;
		unsigned int length;
	} inout[] = {
		{ "", "", 0 },
		{ "\0\0", "", 0 },
		{ "hello", "hello", 5 },
		{ "hel\0lo", "hel", 3 }
	};

	Memblock m;
	unsigned int i;
	for (i = 0; i < sizeof(inout) / sizeof(inout_t); i++) {
		m = Memblock(inout[i].in);
		if (memcmp(m.data, inout[i].data, m.length)) {
			throw Utils::strprintf("Invalid data for input '%s' (expected '%s', got '%s')", inout[i].in, inout[i].data, m.data);
		}
		if (m.length != inout[i].length) {
			throw Utils::strprintf("Invalid length for input '%s' (expected '%d', got '%d')", inout[i].in, inout[i].length, m.length);
		}
	}

	m = m;
	if (memcmp(m.data, inout[i-1].data, m.length)) {
		throw Utils::strprintf("Invalid data for input '%s' (expected '%s', got '%s')", inout[i-1].in, inout[i-1].data, m.data);
	}
	if (m.length != inout[i-1].length) {
		throw Utils::strprintf("Invalid length for input '%s' (expected '%d', got '%d')", inout[i-1].in, inout[i-1].length, m.length);
	}

	Memblock empty;
	m = empty;
	if (m.data != NULL) {
		throw Utils::strprintf("Invalid data for empty block (expected 'NULL', got '%s')", m.data);
	}
	if (m.length != 0) {
		throw Utils::strprintf("Invalid length for empty block (expected '0', got '%d')", m.length);
	}
}


// Tests for Memblock::operator+=()
static void test_memblock_append()
{
	struct inout_t {
		const char *in1;
		const char *in2;
		const char *data;
		unsigned int length;
	} inout[] = {
		{ "", "", "", 0 },
		{ "\0\0", "", "", 0 },
		{ "hello", "", "hello", 5 },
		{ "", "bla", "bla", 3 },
		{ "blu", "bla", "blubla", 6 },
		{ "hel\0lo", "hll", "helhll", 6 }
	};

	for (unsigned int i = 0; i < sizeof(inout) / sizeof(inout_t); i++) {
		Memblock m(inout[i].in1);
		m += Memblock(inout[i].in2);
		if (memcmp(m.data, inout[i].data, m.length)) {
			throw Utils::strprintf("Invalid data for input '%s,%s' (expected '%s', got '%s')", inout[i].in1, inout[i].in2, inout[i].data, m.data);
		}
		if (m.length != inout[i].length) {
			throw Utils::strprintf("Invalid length for input '%s,%s' (expected '%d', got '%d')", inout[i].in1, inout[i].in2, inout[i].length, m.length);
		}
	}
}


// Unit test entry point
int test_memblock(bool verbose)
{
	struct part_t {
		const char *name;
		void (*function)();
	} parts[] = {
		{ "Memblock::Memblock()", test_memblock_constructors },
		{ "Memblock::operator=()", test_memblock_assign },
		{ "Memblock::operator+=()", test_memblock_append }
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
