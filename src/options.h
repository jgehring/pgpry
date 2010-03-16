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
 * file: options.h
 * Command line option parsing
 */


#ifndef OPTIONS_H_
#define OPTIONS_H_


#include <map>
#include <string>

#include "main.h"

class ConfReader;
class ConfWriter;


class Options
{
	public:
		Options();

		void parse(int argc, char **argv);

		void printHelp() const;
		void printVersion() const;
		void printGuesserList() const;
		void printGuesserHelp(const std::string &name) const;

		bool helpRequested() const;
		bool versionRequested() const;
		bool guesserListRequested() const;
		bool mayResume() const;
		std::string guesser() const;
		const std::map<std::string, std::string> &guesserOptions() const;
		uint32_t numTesters() const;
		bool useRegexFiltering() const;
		std::string regexFile() const;
		uint32_t numRegexFilters() const;
		bool usePrefixSuffixFiltering() const;
		const std::vector<std::string> &prefixes() const;
		const std::vector<std::string> &suffixes() const;

		void save(ConfWriter *writer) const;
		void load(ConfReader *reader);

	private:
		void parse(const std::vector<std::string> &args);
		void reset();
		static void printOption(const std::string &option, const std::string &text);

	private:
		std::vector<std::string> m_commandLine;
		bool m_help;
		bool m_version;
		bool m_listGuessers;
		bool m_mayResume;
		std::string m_guesser;
		std::map<std::string, std::string> m_guesserOptions;
		uint32_t m_numTesters;
		std::string m_regexFile;
		uint32_t m_numRegexFilters;
		std::vector<std::string> m_prefixes;
		std::vector<std::string> m_suffixes;
};


#endif
