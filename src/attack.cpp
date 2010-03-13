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
#include <fstream>

#include "buffer.h"
#include "confio.h"
#include "guessers.h"
#include "key.h"
#include "options.h"
#include "regexfilter.h"
#include "sysutils.h"
#include "tester.h"

#include "attack.h"


// Static variables
Attack *Attack::ctx = NULL;


// Signal handler class
class AttackSigHandler : public SysUtils::SigHandler
{
	public:
		AttackSigHandler(Attack *attack)
			: m_attack(attack)
		{

		}

	protected:
		void setup(sigset_t *set)
		{
			sigaddset(set, SIGINT);
		}

		bool handle(int32_t sig)
		{
			std::cerr << "Interrupt catched, saving state..." << std::endl;
			m_attack->saveAndAbort();
			return false;
		}

	private:
		Attack *m_attack;
};


// Private constructor
Attack::Attack(const Options &options)
	: m_options(options), m_buffer(NULL)
{

}

// Performs the brute-force attack
int32_t Attack::run(const Key &key, const Options &options, ConfReader *reader)
{
	if (ctx) {
		delete ctx;
	}
	ctx = new Attack(options);

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

	// Start signal handler
	SysUtils::SigHandler::block(SIGINT);
	AttackSigHandler sigHandler(ctx);
	sigHandler.start();

	// Start threads 
	for (uint32_t i = 0; i < ctx->m_guessers.size(); i++) {
		if (reader) {
			try {
				ctx->m_guessers[i]->loadState(reader);
			} catch (const std::string &str) {
				std::cerr << "Error loading guesser state: " << str << std::endl;
				return EXIT_FAILURE;
			} catch (const char *str) {
				std::cerr << "Error loading guesser state: " << str << std::endl;
				return EXIT_FAILURE;
			}
		}
		ctx->m_guessers[i]->start(reader != NULL);
	}
	for (uint32_t i = 0; i < ctx->m_regexFilters.size(); i++) {
		ctx->m_regexFilters[i]->start();
	}
	for (uint32_t i = 0; i < ctx->m_testers.size(); i++) {
		ctx->m_testers[i]->start();
	}

	// Now all we've got to do is wait
	ctx->m_condition.wait(&ctx->m_mutex);

	switch (ctx->m_status) {
		case STATUS_SUCCESS:
			std::cout << "SUCCESS: Found pass phrase: '" << ctx->m_phrase << "'." << std::endl;
			break;
		case STATUS_EXHAUSTED:
			std::cout << "SORRY, the key space is exhausted. The attack failed." << std::endl;
			break;
		case STATUS_FAILURE:
			std::cout << "ERROR: " << ctx->m_errString << std::endl;
			break;
		default:
			break;
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

	ctx->fillBuffer();

	ctx->m_mutex.lock();
	ctx->m_condition.wakeAll();
	ctx->m_mutex.unlock();
}

// Called whenever a problematic error appears, e.g. the key uses an unsupported algorithm
void Attack::error(const std::string &errString)
{
	ctx->m_mutex.lock();
	ctx->m_status = STATUS_FAILURE;
	ctx->m_errString = errString;
	ctx->m_condition.wakeAll();
	ctx->m_mutex.unlock();
}

// Saves the current guesser state and aborts the attack
void Attack::saveAndAbort()
{
	ctx->m_mutex.lock();
	ctx->m_status = STATUS_ABORTED;
	ctx->m_mutex.unlock();

	ctx->fillBuffer();

	// Wait for guessers and save their state
	std::ofstream out(PGPRY_STATEFILE);
	ConfWriter *writer;
	if (out.is_open()) {
		writer = new ConfWriter(out);
	} else {
		writer = new ConfWriter(std::cout);
	}
	writer->putComment("");
	writer->putComment(PACKAGE_NAME" "PACKAGE_VERSION" - State dump");
	writer->putComment("");
	writer->putComment("Command-line options");
	ctx->m_options.save(writer);
	writer->putComment("Guesser state");
	for (uint32_t i = 0; i < ctx->m_guessers.size(); i++) {
		ctx->m_guessers[i]->wait();
		ctx->m_guessers[i]->saveState(writer);
	}
	delete writer;
	out.close();

	ctx->m_mutex.lock();
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
	} else {
		std::cerr << "ERROR: No such guessing method: " << options.guesser() << std::endl;
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

// Inserts empty memory blocks into the buffer. The tester thread will finish
// if the attack status isn't RUNNING and it received an empty memory block from the buffer
void Attack::fillBuffer()
{
	uint32_t n = m_buffer->size();
	for (uint32_t i = 0; i < n; i++) {
		m_buffer->put(Memblock());
	}
}
