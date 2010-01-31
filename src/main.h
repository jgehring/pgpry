/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: main.h
 * Common types and definitions
 */


#ifndef MAIN_H_
#define MAIN_H_


#include "config.h"


#ifndef HAVE_STDINT_H
 typedef signed char int8_t;
 typedef unsigned char uint8_t;
 typedef signed short int16_t;
 typedef unsigned short uint16_t;
 typedef signed int int32_t;
 typedef unsigned int uint32_t;
#else
 #include <stdint.h>
#endif


#endif // MAIN_H_
