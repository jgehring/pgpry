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
 * file: sysutils/sysutils.h
 * Various system utilities and wrapper classes
 */


#ifndef SYSUTILS_H_
#define SYSUTILS_H_


#include "main.h"

#include <string>

#include <regex.h>
#include <signal.h>
#include <sys/time.h>

#include "memblock.h"
#include "threads.h"


namespace SysUtils
{

class Regex
{
	public:
		Regex(const std::string &pattern);
		Regex(const Regex &other);
		~Regex();

		bool matches(const std::string &str) const {
			return (regexec(&m_rx, str.c_str(), 0, NULL, 0) == 0);
		}
		bool matches(const Memblock &mblock) const {
			return (mblock.data && regexec(&m_rx, (const char *)mblock.data, 0, NULL, 0) == 0);
		}

		Regex &operator=(const Regex &other);

	private:
		std::string errorString(int32_t error);

	private:
		regex_t m_rx;
		std::string m_pattern;
};


class Watch
{
	public:
		Watch();

		void start();
		uint32_t elapsed() const {
			timeval c;
			gettimeofday(&c, NULL);	
 			return (c.tv_sec - m_tv.tv_sec) * 1000 + (c.tv_usec - m_tv.tv_usec) / 1000;
 		}

	private:
		timeval m_tv;
};


class SigHandler : public Thread
{
	public:
		SigHandler();

		static bool block(int32_t sig);

	protected:
		void run();

		virtual void setup(sigset_t *set) = 0;
		virtual bool handle(int32_t sig) = 0;
};

} // namespace SysUtils


#endif // SYSUTILS_H_
