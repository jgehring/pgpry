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
 * file: main.h
 * Common types and definitions
 */


#ifndef MAIN_H_
#define MAIN_H_


#include "config.h"


#define PGPRY_STATEFILE "state"


// Standard integer types
#ifdef HAVE_STDINT_H
 #include <stdint.h>
#endif
#ifndef int8_t
 typedef signed char int8_t;
#endif
#ifndef uint8_t
 typedef unsigned char uint8_t;
#endif
#ifndef int16_t
 typedef signed short int16_t;
#endif
#ifndef uint16_t
 typedef unsigned short uint16_t;
#endif
#ifndef int32_t
 typedef signed int int32_t;
#endif
#ifndef uint32_t
 typedef unsigned int uint32_t;
#endif


#endif // MAIN_H_
