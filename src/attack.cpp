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

#include "attack.h"


// Static variables
Key Attack::m_key;
Memblock Attack::m_phrase;
std::vector<Guessers::Guesser *> Attack::m_guessers;
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
	Buffer buffer;
	m_guessers = setupGuessers(&buffer, options);
	if (m_guessers.empty()) {
		return EXIT_FAILURE;
	}

	m_crackers = setupCrackers(key, &buffer, options);
	if (m_crackers.empty()) {
		return EXIT_FAILURE;
	}

	// Start threads 
	for (uint32_t i = 0; i < m_crackers.size(); i++) {
		m_crackers[i]->start();
	}
	for (uint32_t i = 0; i < m_guessers.size(); i++) {
		m_guessers[i]->start();
	}

	// Now all we've got to do is wait
	Mutex condMutex;
	Attack::m_condition.wait(&condMutex);

	Attack::m_mutex.lock();
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
	Attack::m_mutex.unlock();

	Attack::m_phrase = mblock;
	m_condition.wake();
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

// Sets up the pass phrase testers
std::vector<Crackers::Cracker *> Attack::setupCrackers(const Key &key, Buffer *in, const Options &options)
{
	std::vector<Crackers::Cracker *> crackers;
	Crackers::Cracker *c = Crackers::crackerFor(key, in);
	if (c) {
		crackers.push_back(c);
	} else {
		std::cerr << "Error: Unsupported hash or cipher algorithm" << std::endl;
		std::cerr << (int)key.string2Key().hashAlgorithm() << std::endl;
	}
	return crackers;
}
