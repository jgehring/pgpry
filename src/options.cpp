/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: options.cpp
 * Command line option parsing
 */


#include <iostream>

#include "utils.h"

#include "options.h"


// Constructor
Options::Options()
{
	reset();
}

// The actual parsing
void Options::parse(int argc, char **argv)
{
	bool gopts = false;
	for (int32_t i = 1; i < argc; i++) {
		std::string a(argv[i]);

		if (gopts) {
			std::string::size_type pos = a.find("=");
			if (pos != std::string::npos) {
				m_guesserOptions[a.substr(0, pos)] = a.substr(pos+1);
				continue;
			}
		}

		if (a == "-?" || a == "-h" || a == "--help") {
			m_help = true;
		} else if (a == "--version") {
			m_version = true;
		} else if (a == "-g" && i < argc-1) {
			m_guesser = argv[++i];
		} else if (!a.compare(0, 10, "--guesser=")) {
			m_guesser = a.substr(10);
		} else if (a == "-o" || a == "--options") {
			gopts = true;
		} else if (a == "-j" && i < argc-1) {
			if (!Utils::str2int(argv[++i], &m_numCrackers)) {
                throw Utils::strprintf("Number expected (got %s)", argv[i]);
			}
		} else if (!a.compare(0, 7, "--jobs=")) {
			if (!Utils::str2int(a.substr(7), &m_numCrackers)) {
                throw Utils::strprintf("Number expected (got %s)", a.substr(7).c_str());
			}
        } else if (!a.compare(0, 10, "--regexes=")) {
            m_regexFile = a.substr(10);
        } else if (a == "-r" && i < argc-1) {
            if (!Utils::str2int(argv[++i], &m_numRegexFilters)) {
                throw Utils::strprintf("Number expected (got %s)", argv[i]);
            }
        } else if (!a.compare(0, 13, "--regex-jobs=")) {
			if (!Utils::str2int(a.substr(13), &m_numRegexFilters)) {
                throw Utils::strprintf("Number expected (got %s)", a.substr(13).c_str());
			}
		} else {
			throw Utils::strprintf("Unkown argument %s", argv[i]);
		}
	}
}

// Prints a help screen
void Options::printHelp()
{
	std::cout << "USAGE: " << PACKAGE_NAME << " [options]" << std::endl;
	std::cout << std::endl;
	std::cout << "Valid options:" << std::endl;
	printOption("-h, --help, -?", "Output basic usage information");
	printOption("--version", "Output version information");
	printOption("-g METHOD, --guesser=METHOD", "Use METHOD for guessing phrases");
	printOption("-l, --list-guessers", "List available guessing methods");
	printOption("-o OPTION1=VALUE1 OPTION2=VALUE2 ..., --options OPTION1=VALUE1 ...", "Set guessing options (name-value pairs)");
    printOption("--regexes=FILE", "Read regular expressions from FILE");
	printOption("-j N, --jobs=N", "Use N cracker (phrase testing) jobs");
    printOption("-r N, --regex-jobs=N", "Use N regular expression filtering jobs");
	std::cout << std::endl;
	std::cout << "The key data will be read from stdin." << std::endl;
	std::cout << std::endl;
	std::cout << "Report bugs to " << "<" << PACKAGE_BUGREPORT ">" << std::endl;
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

uint32_t Options::numCrackers() const
{
	return m_numCrackers;
}

bool Options::useRegexFiltering() const
{
    return !m_regexFile.empty();
}

const std::string &Options::regexFile() const
{
    return m_regexFile;
}

uint32_t Options::numRegexFilters() const
{
    return m_numRegexFilters;
}

// Sets default values
void Options::reset()
{
	m_help = false;
	m_version = false;
	m_guesser = "incremental";
	m_guesserOptions.clear();
	m_numCrackers = 1;
    m_regexFile = std::string();
    m_numRegexFilters = 1;
}

// Utility function for printing a help screen option
void Options::printOption(const std::string &option, const std::string &text)
{
	std::cout << "  " << option;
	if (option.length() < 30) {
		for (int i = option.length(); i < 32; i++) {
			std::cout << " ";
		}
	} else {
		std::cout << std::endl;
		for (int i = 0; i < 34; i++) {
			std::cout << " ";
		}
	}

	std::cout << text << std::endl;
}
