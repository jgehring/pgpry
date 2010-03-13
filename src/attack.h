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
 * file: attack.h
 * Static attack context
 */


#ifndef ATTACK_H_
#define ATTACK_H_


#include "main.h"

#include <string>
#include <vector>

#include "key.h"
#include "memblock.h"
#include "threads.h"

class Buffer;
class ConfReader;
class Options;
class RegexFilter;
class Tester;
namespace Guessers {
	class Guesser;
}


class Attack
{
	public:
		enum Status
		{
			STATUS_RUNNING = 0,
			STATUS_SUCCESS = 1,
			STATUS_EXHAUSTED = 2,
			STATUS_FAILURE = 3,
			STATUS_ABORTED = 4
		};

	public:
		static int32_t run(const Key &key, const Options &options, ConfReader *reader = NULL);

		static void phraseFound(const Memblock &mblock);
		static void exhausted();
		static void error(const std::string &err);
		static void saveAndAbort();

		static Status status();

	private:
		Attack(const Options &options);

		static std::vector<Guessers::Guesser *> setupGuessers(Buffer *out, const Options &options);
        static std::vector<RegexFilter *> setupRegexFilters(Buffer *in, Buffer *out, const Options &options);
		static std::vector<Tester *> setupTesters(const Key &key, Buffer *in, const Options &options);

		void fillBuffer();

	private:
		static Attack *ctx;

		const Options &m_options;
		Key m_key;
		Memblock m_phrase;
		Buffer *m_buffer;
		std::vector<Guessers::Guesser *> m_guessers;
        std::vector<RegexFilter *> m_regexFilters;
		std::vector<Tester *> m_testers;
		std::string m_errString;
		Status m_status;
		SysUtils::Mutex m_mutex;
		SysUtils::WaitCondition m_condition;
};


// Inlined functions
inline Attack::Status Attack::status()
{
	Status status;
	ctx->m_mutex.lock();
	status = ctx->m_status;
	ctx->m_mutex.unlock();
	return status;
}


#endif // ATTACK_H_
