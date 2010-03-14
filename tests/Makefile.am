# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
		echo '# Signature of the current package.' && \
		echo 'm4_define([AT_PACKAGE_NAME],' && \
		echo '  [@PACKAGE_NAME@])' && \
		echo 'm4_define([AT_PACKAGE_TARNAME],' && \
		echo '  [@PACKAGE_TARNAME@])' && \
		echo 'm4_define([AT_PACKAGE_VERSION],' && \
		echo '  [@PACKAGE_VERSION@])' && \
		echo 'm4_define([AT_PACKAGE_STRING],' && \
		echo '  [@PACKAGE_STRING@])' && \
		echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
		echo '  [@PACKAGE_BUGREPORT@])'; \
		echo 'm4_define([AT_PACKAGE_URL],' && \
		echo '  [@PACKAGE_URL@])'; \
	} >'$(srcdir)/package.m4'

SUBDIRS = utests

EXTRA_DIST = \
	testsuite.at \
	test_behaviour.at \
	test_units.at \
	$(srcdir)/package.m4 \
	$(TESTSUITE) \
	atlocal.in \
	formats/README \
	formats/check.pl \
	formats/genkeys.java \
	formats/genkeys.sh \
	formats/keys.tar.bz2

TESTSUITE = $(srcdir)/testsuite

# This should fix VPATH builds
formats-check.pl: formats/check.pl
	cp $(srcdir)/formats/check.pl formats-check.pl
formats-keys.tar.bz2: formats/keys.tar.bz2
	cp $(srcdir)/formats/keys.tar.bz2 formats-keys.tar.bz2
all-local: formats-check.pl formats-keys.tar.bz2
CLEANFILES = formats-check.pl formats-keys.tar.bz2 atconfig

check-local: atconfig atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

installcheck-local: atconfig atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
