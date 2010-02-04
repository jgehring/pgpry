/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: attack.h
 * Static attack context
 */


#ifndef ATTACK_H_
#define ATTACK_H_


#include "main.h"

#include <vector>

#include "key.h"
#include "mutex.h"
#include "waitcondition.h"
#include "memblock.h"

class Buffer;
class Options;
namespace Crackers {
	class Cracker;
}
namespace Guessers {
	class Guesser;
}


class Attack
{
	public:
		static int32_t run(const Key &key, const Options &options);

		static void phraseFound(const Memblock &mblock);
		static bool successful();

	private:
		static std::vector<Guessers::Guesser *> setupGuessers(Buffer *out, const Options &options);
		static std::vector<Crackers::Cracker *> setupCrackers(const Key &key, Buffer *in, const Options &options);

	private:
		static Key m_key;
		static Memblock m_phrase;
		static std::vector<Guessers::Guesser *> m_guessers;
		static std::vector<Crackers::Cracker *> m_crackers;
		static bool m_success;
		static Mutex m_mutex;
		static WaitCondition m_condition;
};


// Inlined functions
inline bool Attack::successful()
{
	bool success;
	Attack::m_mutex.lock();
	success = Attack::m_success;
	Attack::m_mutex.unlock();
	return success;
}


#endif // ATTACK_H_
