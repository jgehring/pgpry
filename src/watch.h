/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: watch.h
 * Small stop watch class
 */


#ifndef WATCH_H_
#define WATCH_H_


#include <sys/time.h>

#include "main.h"


class Watch
{
	public:
		Watch();

		void start();
		uint32_t elapsed() const;

	private:
		timeval m_tv;
};


// Inlined functions
inline uint32_t Watch::elapsed() const
{
	timeval c;
	gettimeofday(&c, NULL);	
	return (c.tv_sec - m_tv.tv_sec) * 1000 + (c.tv_usec - m_tv.tv_usec) / 1000;
}


#endif // WATCH_H_
