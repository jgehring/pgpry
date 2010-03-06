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
 * file: attack.cpp
 * Static attack context
 */


#include <cstdlib>
#include <iostream>

#include "buffer.h"
#include "guessers.h"
#include "key.h"
#include "options.h"
#include "regexfilter.h"
#include "tester.h"

#include "attack.h"


// Static variables
Key Attack::m_key;
Memblock Attack::m_phrase;
Buffer *Attack::m_buffer = NULL;
std::vector<Guessers::Guesser *> Attack::m_guessers;
std::vector<RegexFilter *> Attack::m_regexFilters;
std::vector<Tester *> Attack::m_testers;
std::string Attack::m_errString;
Attack::Status Attack::m_status;
SysUtils::Mutex Attack::m_mutex;
SysUtils::WaitCondition Attack::m_condition;


// Performs the brute-force attack
int32_t Attack::run(const Key &key, const Options &options)
{
	Attack::m_key = key;
	Attack::m_status = STATUS_RUNNING;

	// Setup threads
	Buffer buffer, buffer2;
	m_guessers = setupGuessers(&buffer, options);
	if (m_guessers.empty()) {
		return EXIT_FAILURE;
	}

    if (options.useRegexFiltering()) {
        m_regexFilters = setupRegexFilters(&buffer, &buffer2, options);
        m_testers = setupTesters(key, &buffer2, options);
    } else {
        m_testers = setupTesters(key, &buffer, options);
    }
	if (m_testers.empty()) {
		return EXIT_FAILURE;
	}

	Attack::m_buffer = &buffer;
	Attack::m_mutex.lock();

	// Start threads 
	for (uint32_t i = 0; i < m_guessers.size(); i++) {
		m_guessers[i]->start();
	}
	for (uint32_t i = 0; i < m_regexFilters.size(); i++) {
		m_regexFilters[i]->start();
	}
	for (uint32_t i = 0; i < m_testers.size(); i++) {
		m_testers[i]->start();
	}

	// Now all we've got to do is wait
	Attack::m_condition.wait(&Attack::m_mutex);

	if (Attack::m_status == STATUS_SUCCESS) {
		std::cout << "SUCCESS: Found pass phrase: '" << m_phrase.data << "'." << std::endl;
	} else if (Attack::m_status == STATUS_EXHAUSTED) {
		std::cout << "SORRY, the key space is exhausted. The attack failed." << std::endl;
	} else { // STATUS_FAILURE
		std::cout << "ERROR: " << Attack::m_errString << std::endl;
	}

	Attack::m_mutex.unlock();

	// Wait for threads
	for (uint32_t i = 0; i < m_testers.size(); i++) {
		m_testers[i]->wait();
	}
	for (uint32_t i = 0; i < m_regexFilters.size(); i++) {
		m_regexFilters[i]->wait();
	}
	for (uint32_t i = 0; i < m_guessers.size(); i++) {
		m_guessers[i]->wait();
	}

	return (Attack::m_status == STATUS_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE);
}

// Called by a cracker which has discovered the pass phrase
void Attack::phraseFound(const Memblock &mblock)
{
	// TODO: Check the solution once more by trying to unlock the key

	Attack::m_mutex.lock();
	Attack::m_status = STATUS_SUCCESS;

	Attack::m_phrase = mblock;
	Attack::m_condition.wakeAll();
	Attack::m_mutex.unlock();
}

// Called by a guesser if it's out of phrases
void Attack::exhausted()
{
	Attack::m_mutex.lock();
	Attack::m_status = STATUS_EXHAUSTED;
	Attack::m_mutex.unlock();

	// Insert empty memory blocks into the buffer. The tester thread will finish
	// if the attack status isn't RUNNING and it received an empty memory block from the buffer
	uint32_t n = Attack::m_buffer->size();
	for (uint32_t i = 0; i < n; i++) {
		Attack::m_buffer->put(Memblock());
	}

	Attack::m_mutex.lock();
	Attack::m_condition.wakeAll();
	Attack::m_mutex.unlock();
}

// Called whenever a problematic error appears, i.e. an unsupported algorithm
void Attack::error(const std::string &errString)
{
	Attack::m_mutex.lock();
	Attack::m_status = STATUS_FAILURE;
	Attack::m_errString = errString;
	Attack::m_condition.wakeAll();
	Attack::m_mutex.unlock();
}

// Sets up the pass phrases guessers
std::vector<Guessers::Guesser *> Attack::setupGuessers(Buffer *out, const Options &options)
{
	std::vector<Guessers::Guesser *> guessers;
	Guessers::Guesser *g = Guessers::guesser(options.guesser(), out);
	if (g) {
		g->setup(options.guesserOptions());
		guessers.push_back(g);
	}
	return guessers;
}

// Sets up the regular expression filters
std::vector<RegexFilter *> Attack::setupRegexFilters(Buffer *in, Buffer *out, const Options &options)
{
    std::vector<RegexFilter *> filters;
	for (uint32_t i = 0; i < options.numRegexFilters(); i++) {
        RegexFilter *r = new RegexFilter(in, out);
        if (!r->readExpressions(options.regexFile())) {
            break;
        }
        filters.push_back(r);
    }
    return filters;
}

// Sets up the pass phrase testers
std::vector<Tester *> Attack::setupTesters(const Key &key, Buffer *in, const Options &options)
{
	std::vector<Tester *> testers;
	for (uint32_t i = 0; i < options.numTesters(); i++) {
		testers.push_back(new Tester(key, in));
	}
	return testers;
}
