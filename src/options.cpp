/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: options.cpp
 * Command line option parsing
 */


#include <iostream>

#include "options.h"


// Constructor
Options::Options()
{
	reset();
}

// The actual parsing
void Options::parse(int argc, char **argv)
{
	for (int32_t i = 1; i < argc; i++) {
		std::string a(argv[i]);

		if (a == "-?" || a == "-h" || a == "--help") {
			m_help = true;
		} else if (a == "--version") {
			m_version = true;
		}
	}
}

// Prints a help screen
void Options::printHelp()
{
	std::cout << "USAGE: " << PACKAGE_NAME << " <arguments>" << std::endl;
}

// Prints version information
void Options::printVersion()
{
	std::cout << PACKAGE_NAME << " " << PACKAGE_VERSION << std::endl;
	std::cout << "Copyright (C) 2010 " << "Jonas Gehring <" << PACKAGE_BUGREPORT << ">" << std::endl;
	std::cout << "Released under the GNU General Public License." << std::endl;
}

// Query functions
bool Options::helpRequested() const
{
	return m_help;
}

bool Options::versionRequested() const
{
	return m_version;
}

const std::string &Options::guesser() const
{
	return m_guesser;
}

const std::map<std::string, std::string> &Options::guesserOptions() const
{
	return m_guesserOptions;
}

// Sets default values
void Options::reset()
{
	m_help = false;
	m_version = false;
	m_guesser = "incremental";
	m_guesserOptions.clear();
}
