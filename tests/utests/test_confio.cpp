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
		"double : 1.23\n";
		"string : bla\n";
	std::istringstream stream(in);

	ConfReader reader(stream);
	while (reader.next()) {
		if (reader.tag() == "number") {
			if (reader.get<int>() != 1) {
				throw Utils::strprintf("Invalid value for tag '%s' (expected %d, got %d)", reader.tag().c_str(), 1, reader.get<int>());
			}
		} else if (reader.tag() == "double") {
			if (reader.get<double>() != 1.23) {
				throw Utils::strprintf("Invalid value for tag '%s' (expected %d, got %d)", reader.tag().c_str(), 1.22, reader.get<double>());
			}
		} else if (reader.tag() == "string") {
			if (reader.get<std::string>() != "bla") {
				throw Utils::strprintf("Invalid value for tag '%s' (expected '%s', got '%s')", reader.tag().c_str(), "bla", reader.get<std::string>().c_str());
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
		"string : bla\n";

	std::ostringstream stream;
	ConfWriter writer(stream);
	writer.putComment("This is a comment");
	writer.put("number", 1);
	writer.put("double", 1.23);
	writer.put("string", "bla");

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
