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
 * file: sysutils/threads.cpp
 * Utility and wrapper classes for POSIX threads
 */


#include <cassert>

#include "threads.h"


namespace SysUtils
{

// Constructor
Thread::Thread()
	: m_running(false)
{

}

// Starts the thread
void Thread::start()
{
	assert(m_running == false);
	m_running = true;
	pthread_create(&m_pth, NULL, &Thread::main, this);
}

// Blocks the current thread until this thread has finished
void Thread::wait()
{
	if (m_running) {
		pthread_join(m_pth, 0);
		m_running = false;
	}
}

// Executs the thread's run() function
void *Thread::main(void *obj)
{
	reinterpret_cast<Thread *>(obj)->run();
	return NULL;
}


// Constructor
Mutex::Mutex()
{
	pthread_mutex_init(&m_pmx, NULL);
}

// Destructor
Mutex::~Mutex()
{
	pthread_mutex_destroy(&m_pmx);
}


// Constructor
WaitCondition::WaitCondition()
{
	pthread_cond_init(&m_pcond, NULL);
}

// Destructor
WaitCondition::~WaitCondition()
{
	pthread_cond_destroy(&m_pcond);
}


// Constructor
Semaphore::Semaphore(uint32_t n)
	: m_avail(n)
{
	pthread_mutex_init(&m_mutex, NULL);
	pthread_cond_init(&m_cond, NULL);
}

// Destructor
Semaphore::~Semaphore()
{
	pthread_mutex_destroy(&m_mutex);
	pthread_cond_destroy(&m_cond);
}

} // namespace SysUtils
