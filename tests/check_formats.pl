#!/usr/bin/env perl
#
# pgpry - PGP private key recovery
# Copyright (C) 2010 Jonas Gehring
#

use strict;
use warnings;

my $archive="../../formats/keys.tar.bz2";
my $charset="1234567890";  # Character set used for the test key passwords

# Let's go
print(`pwd`);
print(`echo \$PATH`);
if (not -f $archive) {
	print("ERROR: Test keys archive ($archive) not present\n");
	exit(1);
}

open(TAR, "tar -tjf $archive 2> /dev/null |");
while (<TAR>) {
	chomp();
	next if /\/$/ or /\/null[^\/]*$/; # Skip directories and null keys
	my $key = $_;
	system("tar --to-stdout -xjf $archive $key | pgpry -o charset=$charset") == 0
		or die("pgpry failed for key $key");
}
close(TAR);

exit(0);
