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
 * file: filter.h
 * Abstract filter base class
 */


#ifndef FILTER_H_
#define FILTER_H_


#include "sysutils.h"

class Buffer;


class Filter : public SysUtils::Thread
{
	public:
		Filter(Buffer *in, Buffer *out);

	protected:
		Buffer *m_in;
		Buffer *m_out;
};


#endif // FILTER_H_
