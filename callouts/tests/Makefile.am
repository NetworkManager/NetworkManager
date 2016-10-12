if ENABLE_TESTS

AM_CPPFLAGS = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/callouts \
	-I$(top_builddir)/callouts \
	-DNETWORKMANAGER_COMPILATION \
	-DSRCDIR=\"$(abs_srcdir)\" \
	$(GLIB_CFLAGS)

noinst_PROGRAMS = \
	test-dispatcher-envp

###############################################################################

test_dispatcher_envp_SOURCES = \
	test-dispatcher-envp.c

test_dispatcher_envp_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(top_builddir)/callouts/libnm-dispatcher-core.la \
	$(GLIB_LIBS)

###############################################################################

@VALGRIND_RULES@
TESTS = test-dispatcher-envp

endif

EXTRA_DIST= \
	dispatcher-connectivity-full \
	dispatcher-connectivity-unknown \
	dispatcher-down \
	dispatcher-external \
	dispatcher-up \
	dispatcher-vpn-down \
	dispatcher-vpn-up
