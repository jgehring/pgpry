/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: thread.cpp
 * Simple thread class using Pthreads
 */


#include <cassert>

#include "thread.h"


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
