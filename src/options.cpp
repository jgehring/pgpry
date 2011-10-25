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
 * file: options.cpp
 * Command line option parsing
 */


#include <iostream>

#include "confio.h"
#include "guessers.h"
#include "utils.h"

#include "options.h"


// Constructor
Options::Options()
{
	reset();
}

// Option parsing
void Options::parse(int argc, char **argv)
{
	m_commandLine.clear();
	for (int32_t i = 0; i < argc; i++) {
		m_commandLine.push_back(argv[i]);
	}

	parse(m_commandLine);
}

// Prints a help screen
void Options::printHelp() const
{
	if (!m_guesser.empty()) {
		printGuesserHelp(m_guesser);
		return;
	}

	std::cout << "USAGE: " << PACKAGE_NAME << " [options]" << std::endl;
	std::cout << std::endl;
	std::cout << "Valid options:" << std::endl;
	printOption("-h, --help, -?", "Output basic usage information");
	printOption("--version", "Output version information");
	printOption("-l, --list-guessers", "List available guessing methods");
	printOption("-g METHOD, --guesser=METHOD", "Use METHOD for guessing phrases");
	printOption("-o OPTION1=VALUE1 OPTION2=VALUE2 ..., --options OPTION1=VALUE1 ...", "Set guessing options (name-value pairs)");
	printOption("--regexes=FILE", "Read regular expressions from FILE");
	printOption("--prefixes=LIST", "Prepend prefixes from the comma-seperated LIST");
	printOption("--suffixes=LIST", "Append suffixes from the comma-seperated LIST");
	printOption("-j N, --jobs=N", "Use N cracker (phrase testing) jobs");
	printOption("-r N, --regex-jobs=N", "Use N regular expression filtering jobs");
	printOption("--no-resume", "Always start a new attack");
	std::cout << std::endl;
	std::cout << "The key data will be read from stdin." << std::endl;
	std::cout << std::endl;
	std::cout << "Report bugs to " << "<" << PACKAGE_BUGREPORT ">" << std::endl;
}

// Prints version information
void Options::printVersion() const
{
	std::cout << PACKAGE_NAME << " " << PACKAGE_VERSION << std::endl;
	std::cout << "Copyright (C) 2010-2011 " << "Jonas Gehring <" << PACKAGE_BUGREPORT << ">" << std::endl;
	std::cout << "Released under the GNU General Public License." << std::endl;
}

// Prints a listing of the included guessers
void Options::printGuesserList() const
{
	std::cout << "Available guessing methods:" << std::endl;
	std::cout << std::endl;

	std::vector<std::pair<std::string, std::string> > guessers = Guessers::guessers();
	for (uint32_t i = 0; i < guessers.size(); i++) {
		printOption(guessers[i].first, guessers[i].second);
	}

	std::cout << std::endl;
	std::cout << "Use --guesser=<guesser> --help to list the supported options of a guesser" << std::endl;
}

// Prints a help screen for the given guesser
void Options::printGuesserHelp(const std::string &name) const
{
	Guessers::Guesser *guesser = Guessers::guesser(name, NULL);
	if (guesser == NULL) {
		std::cerr << "ERROR: No such guessing method: " << name << std::endl;
		return;
	}

	std::cout << "Valid options for guessing method '" << name << "':" << std::endl;
	std::vector<std::pair<std::string, std::string> > options = guesser->options();
	for (uint32_t i = 0; i < options.size(); i++) {
		printOption(options[i].first, options[i].second);
	}

	delete guesser;
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

bool Options::guesserListRequested() const
{
	return m_listGuessers;
}

bool Options::mayResume() const
{
	return m_mayResume;
}

std::string Options::guesser() const
{
	if (m_guesser.empty()) {
		return "incremental";
	}
	return m_guesser;
}

const std::map<std::string, std::string> &Options::guesserOptions() const
{
	return m_guesserOptions;
}

uint32_t Options::numTesters() const
{
	return m_numTesters;
}

bool Options::useRegexFiltering() const
{
	return !m_regexFile.empty();
}

std::string Options::regexFile() const
{
	return m_regexFile;
}

uint32_t Options::numRegexFilters() const
{
	return m_numRegexFilters;
}

bool Options::usePrefixSuffixFiltering() const
{
	return (!m_prefixes.empty() || !m_suffixes.empty());
}

const std::vector<std::string> &Options::prefixes() const
{
	return m_prefixes;
}

const std::vector<std::string> &Options::suffixes() const
{
	return m_suffixes;
}

// Saves the current options
void Options::save(ConfWriter *writer) const
{
	for (size_t i = 0; i < m_commandLine.size(); i++) {
		writer->put("arg", m_commandLine[i]);
	}
}

void Options::load(ConfReader *reader)
{
	reset();
	m_commandLine.clear();
	do {
		if (reader->tag() == "arg") {
			m_commandLine.push_back(reader->getstr());
		} else if (!reader->tag().empty()) {
			break;
		}
	} while (reader->next());

	parse(m_commandLine);
}

// The actual parsing
void Options::parse(const std::vector<std::string> &args)
{
	bool gopts = false;
	for (size_t i = 1; i < args.size(); i++) {
		if (gopts) {
			std::string::size_type pos = args[i].find("=");
			if (pos != std::string::npos && args[i].compare(0, 1, "-")) {
				m_guesserOptions[args[i].substr(0, pos)] = args[i].substr(pos+1);
				continue;
			}
		}
		gopts = false;

		if (args[i] == "-?" || args[i] == "-h" || args[i] == "--help") {
			m_help = true;
		} else if (args[i] == "--version") {
			m_version = true;
		} else if (args[i] == "-l" || args[i] == "--list-guessers") {
			m_listGuessers = true;
		} else if (args[i] == "--no-resume") {
			m_mayResume = false;
		} else if (args[i] == "-g" && i < args.size()-1) {
			m_guesser = args[++i];
		} else if (!args[i].compare(0, 10, "--guesser=")) {
			m_guesser = args[i].substr(10);
		} else if (args[i] == "-o" || args[i] == "--options") {
			gopts = true;
		} else if (args[i] == "-j" && i < args.size()-1) {
			if (!Utils::str2int(args[++i], &m_numTesters)) {
				throw Utils::strprintf("Number expected (got %s)", args[i].c_str());
			}
		} else if (!args[i].compare(0, 7, "--jobs=")) {
			if (!Utils::str2int(args[i].substr(7), &m_numTesters)) {
				throw Utils::strprintf("Number expected (got %s)", args[i].substr(7).c_str());
			}
		} else if (!args[i].compare(0, 10, "--regexes=")) {
			m_regexFile = args[i].substr(10);
		} else if (!args[i].compare(0, 11, "--prefixes=")) {
			m_prefixes = Utils::split(args[i].substr(11), ",");
		} else if (!args[i].compare(0, 11, "--suffixes=")) {
			m_suffixes = Utils::split(args[i].substr(11), ",");
		} else if (args[i] == "-r" && i < args.size()-1) {
			if (!Utils::str2int(args[++i], &m_numRegexFilters)) {
				throw Utils::strprintf("Number expected (got %s)", args[i].c_str());
			}
		} else if (!args[i].compare(0, 13, "--regex-jobs=")) {
			if (!Utils::str2int(args[i].substr(13), &m_numRegexFilters)) {
				throw Utils::strprintf("Number expected (got %s)", args[i].substr(13).c_str());
			}
		} else {
			throw Utils::strprintf("Unkown argument %s", args[i].c_str());
		}
	}
}

// Sets default values
void Options::reset()
{
	m_commandLine.clear();
	m_help = false;
	m_version = false;
	m_listGuessers = false;
	m_mayResume = true;
	m_guesser = std::string();
	m_guesserOptions.clear();
	m_numTesters = 1;
	m_regexFile = std::string();
	m_numRegexFilters = 1;
	m_prefixes.clear();
	m_suffixes.clear();
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
