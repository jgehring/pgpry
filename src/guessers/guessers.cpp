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
 * file: guessers.cpp
 * Guesser thread definition and factory
 */


#include <iostream>

#include "attack.h"
#include "buffer.h"
#include "sysutils.h"

#include "guessers.h"

#include "dictguesser.h"
#include "incguesser.h"
#include "randomguesser.h"


namespace Guessers
{

// Constructor
Guesser::Guesser(Buffer *buffer)
	: Thread(), m_buffer(buffer), m_resume(false)
{

}

// Starts the guesser thread
void Guesser::start(bool resume)
{
	m_resume = resume;
	Thread::start();
}

// Sets up the guesser according to the given options
void Guesser::setup(const std::map<std::string, std::string> &)
{
	// The default implementation does nothing
}

// Returns a list of all supported options
std::vector<std::pair<std::string, std::string> > Guesser::options() const
{
	return std::vector<std::pair<std::string, std::string> >();
}

// Saves the guesser state
void Guesser::saveState(ConfWriter *) const
{
	// The default implementation does nothing
}

// Loads the guesser state
void Guesser::loadState(ConfReader *)
{
	// The default implementation does nothing
}

// Main thread loop
void Guesser::run()
{
	if (!m_resume) {
		try {
			init();
		} catch (const std::string &str) {
			Attack::error(str);
			return;
		} catch (const char *str) {
			Attack::error(str);
			return;
		}
	}

    SysUtils::Watch watch;
	int32_t n = 0, numBlocks = 0;

	Memblock blocks[8];
	while (!abortFlag()) {
		for (numBlocks = 0; numBlocks < 8; numBlocks++) {
			if (!guess(&blocks[numBlocks])) {
				break;
			}
		}

		m_buffer->putn(numBlocks, blocks);
		n += numBlocks;

		if (watch.elapsed() > 2000) {
			if (Attack::status() == Attack::STATUS_RUNNING && numBlocks > 0) {
				std::cout << "Rate: " << 1000 * (double)n/watch.elapsed() << " phrases / second. ";
				std::cout << "Phrase: ";
				for (uint32_t i = 0; i < blocks[numBlocks-1].length; i++) {
					std::cout << (char)blocks[numBlocks-1].data[i];
				}
				std::cout << std::endl;
			}
			watch.start();
			n = 0;
		}

		if (numBlocks != 8) {
			Attack::exhausted();
			break;
		}
	}
}

// Initializes the guesser and throws a string on failure
void Guesser::init()
{
	// The default implementation does nothing
}

// Returns a guesser using the given name
Guesser *guesser(const std::string &name, Buffer *buffer)
{
	if (name == "incremental") {
		return new IncrementalGuesser(buffer);
	} else if (name == "random") {
		return new RandomGuesser(buffer);
	} else if (name == "dictionary") {
		return new DictionaryGuesser(buffer);
	}
	return NULL;
}

// Returns a list of all guessers
std::vector<std::pair<std::string, std::string> > guessers()
{
	typedef std::pair<std::string, std::string> strpair_t;
	std::vector<strpair_t> list;
	list.push_back(strpair_t("incremental", "Incremental guessing (\"try them all\")"));
	list.push_back(strpair_t("random", "Random guessing"));
	list.push_back(strpair_t("dictionary", "Dictionary guessing"));
	return list;
}

} // namespace Guessers
