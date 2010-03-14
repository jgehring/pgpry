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

#include <sys/time.h>

#include "threads.h"


namespace SysUtils
{

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
Thread::Thread()
	: m_running(false), m_abort(false)
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

// Sets the abort flag
void Thread::abort()
{
	m_mutex.lock();
	m_abort = true;
	m_mutex.unlock();
}

// Sleeping
void Thread::msleep(int msecs)
{
	// This is from Qt-4.6, qthread_unix.cpp
	struct timeval tv;
	gettimeofday(&tv, 0);

	timespec ti;
	ti.tv_nsec = (tv.tv_usec + (msecs % 1000) * 1000) * 1000;
	ti.tv_sec = tv.tv_sec + (msecs / 1000) + (ti.tv_nsec / 1000000000);
	ti.tv_nsec %= 1000000000;

	pthread_mutex_t mtx;
	pthread_cond_t cnd;

	pthread_mutex_init(&mtx, 0);
	pthread_cond_init(&cnd, 0);

	pthread_mutex_lock(&mtx);
	(void) pthread_cond_timedwait(&cnd, &mtx, &ti);
	pthread_mutex_unlock(&mtx);

	pthread_cond_destroy(&cnd);
	pthread_mutex_destroy(&mtx);
}

// Checks if the abort flag is set
bool Thread::abortFlag()
{
	bool t;
	m_mutex.lock();
	t = m_abort;
	m_mutex.unlock();
	return t;
}

// Executs the thread's run() function
void *Thread::main(void *obj)
{
	reinterpret_cast<Thread *>(obj)->run();
	reinterpret_cast<Thread *>(obj)->m_running = false;
	return NULL;
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
