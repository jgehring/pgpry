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
 * file: utest/main.cpp
 * Program entry point of the unit testing program
 *
 * USAGE:
 *   - List units:   utest --list
 *   - Test unit:    utest <unit>
 */


#include <cstdlib>
#include <cstring>
#include <iostream>


// Prototypes
extern int test_confio(bool verbose);
extern int test_memblock(bool verbose);
extern int test_utils(bool verbose);


// Program entry point
int main(int argc, char **argv)
{
	struct unit_t {
		const char *name;
		int (*function)(bool verbose);
	} units[] = {
		{ "confio", test_confio },
		{ "memblock", test_memblock },
		{ "utils", test_utils }
	};

	if (argc < 2) {
		std::cerr << "Error: Missing argument" << std::endl;
		return EXIT_FAILURE;
	}

	bool verbose = false;
	int index = 1;
	if (!strcmp(argv[1], "--list")) {
		for (unsigned int i = 0; i < sizeof(units) / sizeof(unit_t); i++) {
			std::cout << units[i].name << std::endl;
		}
		return EXIT_SUCCESS;
	} else if (!strcmp(argv[1], "-v")) {
		verbose = true;
		++index;
	}

	if (argc < index+1) {
		std::cerr << "Error: Missing argument" << std::endl;
		return EXIT_FAILURE;
	}

	for (unsigned int i = 0; i < sizeof(units) / sizeof(unit_t); i++) {
		if (!strcmp(argv[index], units[i].name)) {
			return (*units[i].function)(verbose);
		}
	}

	std::cerr << "Error: No such unit: " << argv[index] << std::endl;
	return EXIT_SUCCESS;
}
