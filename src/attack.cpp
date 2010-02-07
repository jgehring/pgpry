/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: attack.cpp
 * Static attack context
 */


#include <cstdlib>
#include <iostream>

#include "buffer.h"
#include "crackers.h"
#include "guessers.h"
#include "key.h"
#include "options.h"
#include "regexfilter.h"

#include "attack.h"


// Static variables
Key Attack::m_key;
Memblock Attack::m_phrase;
std::vector<Guessers::Guesser *> Attack::m_guessers;
std::vector<RegexFilter *> Attack::m_regexFilters;
std::vector<Crackers::Cracker *> Attack::m_crackers;
bool Attack::m_success = false;
Mutex Attack::m_mutex;
WaitCondition Attack::m_condition;


// Performs the brute-force attack
int32_t Attack::run(const Key &key, const Options &options)
{
	Attack::m_key = key;
	Attack::m_success = false;

	// Setup threads
	Buffer buffer, buffer2;
	m_guessers = setupGuessers(&buffer, options);
	if (m_guessers.empty()) {
		return EXIT_FAILURE;
	}

    if (options.useRegexFiltering()) {
        m_regexFilters = setupRegexFilters(&buffer, &buffer2, options);
        m_crackers = setupCrackers(key, &buffer2, options);
    } else {
        m_crackers = setupCrackers(key, &buffer, options);
    }
	if (m_crackers.empty()) {
		return EXIT_FAILURE;
	}

	Attack::m_mutex.lock();

	// Start threads 
	for (uint32_t i = 0; i < m_guessers.size(); i++) {
		m_guessers[i]->start();
	}
	for (uint32_t i = 0; i < m_regexFilters.size(); i++) {
		m_regexFilters[i]->start();
	}
	for (uint32_t i = 0; i < m_crackers.size(); i++) {
		m_crackers[i]->start();
	}

	// Now all we've got to do is wait
	Attack::m_condition.wait(&Attack::m_mutex);

	if (Attack::m_success) {
		std::cout << "SUCCESS: Found pass phrase: '" << m_phrase.data << "'." << std::endl;
	} else {
		std::cout << "SORRY, the key space is exhausted. The attack failed." << std::endl;
	}

	Attack::m_mutex.unlock();

	// Wait for threads
	for (uint32_t i = 0; i < m_crackers.size(); i++) {
		m_crackers[i]->wait();
	}
	for (uint32_t i = 0; i < m_regexFilters.size(); i++) {
		m_regexFilters[i]->wait();
	}
	for (uint32_t i = 0; i < m_guessers.size(); i++) {
		m_guessers[i]->wait();
	}

	return EXIT_SUCCESS;
}

// Called by a cracker which has discovered the pass phrase
void Attack::phraseFound(const Memblock &mblock)
{
	// TODO: Check the solution once more by trying to unlock the key

	Attack::m_mutex.lock();
	Attack::m_success = true;

	Attack::m_phrase = mblock;
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
std::vector<Crackers::Cracker *> Attack::setupCrackers(const Key &key, Buffer *in, const Options &options)
{
	std::vector<Crackers::Cracker *> crackers;
	for (uint32_t i = 0; i < options.numCrackers(); i++) {
		Crackers::Cracker *c = Crackers::crackerFor(key, in);
		if (c) {
			crackers.push_back(c);
		} else {
			std::cerr << "Error: Unsupported hash or cipher algorithm: ";
			std::cerr << (int)key.string2Key().hashAlgorithm() << std::endl;
			break;
		}
	}
	return crackers;
}
