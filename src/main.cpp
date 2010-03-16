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
 * file: main.cpp
 * Program entry point
 */


#include <cstdlib>
#include <fstream>
#include <iostream>

#include "attack.h"
#include "confio.h"
#include "key.h"
#include "options.h"
#include "pistream.h"


// Program entry point
int main(int argc, char **argv)
{
	Options options;
	ConfReader *reader = NULL;

	// Check if there's a state file
	std::ifstream in(PGPRY_STATEFILE);
	try {
		// Parse command line options first
		options.parse(argc, argv);

		// Load state file if allowed and possible
		if (options.mayResume() && in.is_open()) {
			std::cout << "State file found, resuming attack" << std::endl;
			reader = new ConfReader(in);
			options.load(reader);
		}
	} catch (const std::string &str) {
		std::cerr << "Error parsing arguments: " << str << std::endl;
		return EXIT_FAILURE;
	} catch (const char *cstr) {
		std::cerr << "Error parsing arguments: " << cstr << std::endl;
		return EXIT_FAILURE;
	}

	if (options.helpRequested()) {
		options.printHelp();
		return EXIT_SUCCESS;
	} else if (options.versionRequested()) {
		options.printVersion();
		return EXIT_SUCCESS;
	} else if (options.guesserListRequested()) {
		options.printGuesserList();
		return EXIT_SUCCESS;
	}

	// Read key from stdin
	Key key;
	try {
		PIStream in(std::cin);
		in >> key;
	} catch (const std::string &str) {
		std::cerr << "Exception while parsing key: " << str << std::endl;
		return EXIT_FAILURE;
	} catch (const char *cstr) {
		std::cerr << "Exception while parsing key: " << cstr << std::endl;
		return EXIT_FAILURE;
	}

	if (!key.locked()) {
		std::cerr << "Err, this secret key doesn't seem to be encrypted" << std::endl;
		return EXIT_FAILURE;
	}

	// Let's go
	return Attack::run(key, options, reader);
}
