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
Attack *Attack::ctx;


// Private constructor
Attack::Attack()
	: m_buffer(NULL)
{

}

// Performs the brute-force attack
int32_t Attack::run(const Key &key, const Options &options)
{
	if (ctx) {
		delete ctx;
	}
	ctx = new Attack();

	ctx->m_key = key;
	ctx->m_status = STATUS_RUNNING;

	// Setup threads
	Buffer buffer, buffer2;
	ctx->m_guessers = setupGuessers(&buffer, options);
	if (ctx->m_guessers.empty()) {
		return EXIT_FAILURE;
	}

    if (options.useRegexFiltering()) {
        ctx->m_regexFilters = setupRegexFilters(&buffer, &buffer2, options);
        ctx->m_testers = setupTesters(key, &buffer2, options);
    } else {
        ctx->m_testers = setupTesters(key, &buffer, options);
    }
	if (ctx->m_testers.empty()) {
		return EXIT_FAILURE;
	}

	ctx->m_buffer = &buffer;
	ctx->m_mutex.lock();

	// Start threads 
	for (uint32_t i = 0; i < ctx->m_guessers.size(); i++) {
		ctx->m_guessers[i]->start();
	}
	for (uint32_t i = 0; i < ctx->m_regexFilters.size(); i++) {
		ctx->m_regexFilters[i]->start();
	}
	for (uint32_t i = 0; i < ctx->m_testers.size(); i++) {
		ctx->m_testers[i]->start();
	}

	// Now all we've got to do is wait
	ctx->m_condition.wait(&ctx->m_mutex);

	if (ctx->m_status == STATUS_SUCCESS) {
		std::cout << "SUCCESS: Found pass phrase: '" << ctx->m_phrase.data << "'." << std::endl;
	} else if (ctx->m_status == STATUS_EXHAUSTED) {
		std::cout << "SORRY, the key space is exhausted. The attack failed." << std::endl;
	} else { // STATUS_FAILURE
		std::cout << "ERROR: " << ctx->m_errString << std::endl;
	}

	ctx->m_mutex.unlock();

	// Wait for threads
	for (uint32_t i = 0; i < ctx->m_testers.size(); i++) {
		ctx->m_testers[i]->wait();
	}
	for (uint32_t i = 0; i < ctx->m_regexFilters.size(); i++) {
		ctx->m_regexFilters[i]->wait();
	}
	for (uint32_t i = 0; i < ctx->m_guessers.size(); i++) {
		ctx->m_guessers[i]->wait();
	}

	return (ctx->m_status == STATUS_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE);
}

// Called by a cracker which has discovered the pass phrase
void Attack::phraseFound(const Memblock &mblock)
{
	// TODO: Check the solution once more by trying to unlock the key

	ctx->m_mutex.lock();
	ctx->m_status = STATUS_SUCCESS;

	ctx->m_phrase = mblock;
	ctx->m_condition.wakeAll();
	ctx->m_mutex.unlock();
}

// Called by a guesser if it's out of phrases
void Attack::exhausted()
{
	ctx->m_mutex.lock();
	ctx->m_status = STATUS_EXHAUSTED;
	ctx->m_mutex.unlock();

	// Insert empty memory blocks into the buffer. The tester thread will finish
	// if the attack status isn't RUNNING and it received an empty memory block from the buffer
	uint32_t n = ctx->m_buffer->size();
	for (uint32_t i = 0; i < n; i++) {
		ctx->m_buffer->put(Memblock());
	}

	ctx->m_mutex.lock();
	ctx->m_condition.wakeAll();
	ctx->m_mutex.unlock();
}

// Called whenever a problematic error appears, i.e. an unsupported algorithm
void Attack::error(const std::string &errString)
{
	ctx->m_mutex.lock();
	ctx->m_status = STATUS_FAILURE;
	ctx->m_errString = errString;
	ctx->m_condition.wakeAll();
	ctx->m_mutex.unlock();
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
