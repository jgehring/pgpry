#!/bin/sh
#
# pgpry - PGP private key recovery
# Copyright (C) 2010 Jonas Gehring
#

# Run Java program
BCPROV=`ls -1 | grep 'bcprov.*jar'`
BCPG=`ls -1 | grep 'bcpg.*jar'`
javac -extdirs . genkeys.java && java -cp .:${BCPROV}:${BCPG} genkeys

# Archive keys
if [ -d "keys" ]; then
	tar -cjf keys.tar.bz2 keys
fi
