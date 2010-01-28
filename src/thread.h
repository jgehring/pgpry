/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: thread.h
 * Simple thread class using Pthreads
 */


#ifndef THREAD_H_
#define THREAD_H_


#include <pthread.h>


class Thread
{
	public:
		Thread();
		virtual ~Thread() { }

		void start();
		void wait();

	protected:
		virtual void run() = 0;

	private:
		static void *main(void *obj);

	private:
		pthread_t m_pth;
		volatile bool m_running;
};


#endif // THREAD_H_
