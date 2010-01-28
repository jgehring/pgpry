/*
 * pgpry alpha - PGP private key password recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * file: packetheader.h
 * Represents a PGP packet header
 */


#ifndef PACKETHEADER_H_
#define PACKETHEADER_H_


#include "main.h"

class PIStream;
class POStream;


class PacketHeader
{
	public:
		typedef enum {
			FORMAT_UNKOWN = -1,
			FORMAT_OLD,
			FORMAT_NEW
		} Format;

		typedef enum {
			TYPE_UNKOWN = -1,
			TYPE_SECRET_KEY = 5,
			TYPE_PUBLIC_KEY = 6
		} Type;

	public:
		PacketHeader();

		bool valid() const;
		Format format() const;
		Type type() const;
		int32_t length() const;

		PIStream &operator<<(PIStream &in);
		POStream &operator>>(POStream &out);

	private:
		Format m_format;
		Type m_type;
		int32_t m_length;
};


// Convenience operators
inline PIStream &operator>>(PIStream &in, PacketHeader &header)
{
	return (header << in);
}

inline POStream &operator<<(POStream &out, PacketHeader &header)
{
	return (header >> out);
}


#endif // PACKETHEADER_H_
