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
 * file: utest/test_confio.cpp
 * Unit tests for ConfWriter and ConfReader
 */

#include <cstdlib>
#include <iostream>

#include "confio.h"
#include "utils.h"


static void test_confio_read()
{
	std::string in = \
		"# This is a comment\n" \
		"number : 1\n" \
		"double : 1.23\n" \
		"boolean : 0\n" \
		"string : bla\n" \
		"string_ws : bla blubb\n" \
		"number_vector : 1,2,3\n" \
		"double_vector : 1.23,2.34,-3.3\n" \
		"string_vector : bla,blubb,blobb,plipp\n";
	std::istringstream stream(in);

	ConfReader reader(stream);
	while (reader.next()) {
		if (reader.tag() == "number") {
			if (reader.getint() != 1) {
				throw Utils::strprintf("Invalid value for tag '%s' (expected %d, got %d)", reader.tag().c_str(), 1, reader.getint());
			}
		} else if (reader.tag() == "double") {
			if (reader.getdouble() != 1.23) {
				throw Utils::strprintf("Invalid value for tag '%s' (expected %d, got %d)", reader.tag().c_str(), 1.23, reader.getdouble());
			}
		} else if (reader.tag() == "boolean") {
			if (reader.getbool() != false) {
				throw Utils::strprintf("Invalid value for tag '%s' (expected %d, got %d)", reader.tag().c_str(), false, reader.getbool());
			}
		} else if (reader.tag() == "string") {
			if (reader.getstr() != "bla") {
				throw Utils::strprintf("Invalid value for tag '%s' (expected '%s', got '%s')", reader.tag().c_str(), "bla", reader.getstr().c_str());
			}
		} else if (reader.tag() == "string_ws") {
			if (reader.getstr() != "bla blubb") {
				throw Utils::strprintf("Invalid value for tag '%s' (expected '%s', got '%s')", reader.tag().c_str(), "bla blubb", reader.getstr().c_str());
			}
		} else if (reader.tag() == "number_vector") {
			int numbers[3];
			int n = reader.getints(numbers, 3);
			if (n != 3) {
				throw Utils::strprintf("Invalid value for tag '%s' (expected %d elements, got %d)", reader.tag().c_str(), 3, n);
			}
			int expected[3] = {1, 2, 3};
			for (int i = 0; i < n; i++) {
				if (numbers[i] != expected[i]) {
					throw Utils::strprintf("Invalid value for tag '%s' (expected %d at position %d, got %d)", reader.tag().c_str(), expected[i], i, numbers[i]);
				}
			}
		} else if (reader.tag() == "double_vector") {
			double doubles[3];
			int n = reader.getdoubles(doubles, 3);
			if (n != 3) {
				throw Utils::strprintf("Invalid value for tag '%s' (expected %d elements, got %d)", reader.tag().c_str(), 3, n);
			}
			double expected[3] = {1.23, 2.34, -3.3};
			for (int i = 0; i < n; i++) {
				if (doubles[i] != expected[i]) {
					throw Utils::strprintf("Invalid value for tag '%s' (expected %g at position %d, got %g)", reader.tag().c_str(), expected[i], i, doubles[i]);
				}
			}
		} else if (reader.tag() == "string_vector") {
			std::string strings[4];
			int n = reader.getstrs(strings, 4);
			if (n != 4) {
				throw Utils::strprintf("Invalid value for tag '%s' (expected %d elements, got %d)", reader.tag().c_str(), 4, n);
			}
			std::string expected[4] = {"bla", "blubb", "blobb", "plipp"};
			for (int i = 0; i < n; i++) {
				if (strings[i] != expected[i]) {
					throw Utils::strprintf("Invalid value for tag '%s' (expected '%s' at position %d, got '%s')", reader.tag().c_str(), expected[i].c_str(), i, strings[i].c_str());
				}
			}
		} else {
			throw Utils::strprintf("Unexpected tag: '%s'", reader.tag().c_str());
		}
	}
}

static void test_confio_write()
{
	std::string out = \
		"# This is a comment\n" \
		"number : 1\n" \
		"double : 1.23\n" \
		"boolean : 1\n" \
		"string : bla\n" \
		"string_ws : bla blubb\n" \
		"number_vector : 1,2,3\n" \
		"double_vector : 1.23,2.34,-3.3\n" \
		"string_vector : bla,blubb,blobb,plipp\n";

	std::ostringstream stream;
	ConfWriter writer(stream);
	writer.putComment("This is a comment");
	writer.put("number", 1);
	writer.put("double", 1.23);
	writer.put("boolean", true);
	writer.put("string", "bla");
	writer.put("string_ws", "bla blubb");
	int numbers[] = {1, 2, 3};
	writer.put("number_vector", numbers, 3);
	double doubles[] = {1.23, 2.34, -3.3};
	writer.put("double_vector", doubles, 3);
	std::string strings[] = {"bla", "blubb", "blobb", "plipp"};
	writer.put("string_vector", strings, 4);

	if (stream.str() != out) {
		throw Utils::strprintf("Output does not match:\n'%s' != '%s'", stream.str().c_str(), out.c_str());
	}
}


// Unit test entry point
int test_confio(bool verbose)
{
	struct part_t {
		const char *name;
		void (*function)();
	} parts[] = {
		{ "ConfReader", test_confio_read },
		{ "ConfWriter", test_confio_write },
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
