/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: options.h
 * Command line option parsing
 */


#ifndef OPTIONS_H_
#define OPTIONS_H_


#include <map>
#include <string>

#include "main.h"


class Options
{
	public:
		Options();

		void parse(int argc, char **argv);

		static void printHelp();
		static void printVersion();

		bool helpRequested() const;
		bool versionRequested() const;
		const std::string &guesser() const;
		const std::map<std::string, std::string> &guesserOptions() const;

	private:
		void reset();
		static void printOption(const std::string &option, const std::string &text);

	private:
		bool m_help;
		bool m_version;
		std::string m_guesser;
		std::map<std::string, std::string> m_guesserOptions;
};


#endif
