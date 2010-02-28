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

EXTRA_DIST = testsuite.at $(srcdir)/package.m4 $(TESTSUITE) atlocal.in
TESTSUITE = $(srcdir)/testsuite

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


#
# Test programs
#

#bin_PROGRAMS = cwbp_test_utils
#cwbp_test_utils_SOURCES = \
#    test_utils.c
#
#AM_CFLAGS = -Wall -I$(top_srcdir) \
#    $(APR_CFLAGS) $(APR_CPPFLAGS) $(APR_INCLUDES)
#
#LIBS += $(APR_LIBS) \
#    $(top_srcdir)/cwbp/libcwbp.la
