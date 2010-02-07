/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
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
	assert(m_running == true);
	pthread_join(m_pth, 0);
	m_running = true;
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
