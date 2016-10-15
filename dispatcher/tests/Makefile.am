if ENABLE_TESTS

AM_CPPFLAGS = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/dispatcher \
	-I$(top_builddir)/dispatcher \
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
	$(top_builddir)/dispatcher/libnm-dispatcher-core.la \
	$(GLIB_LIBS)

###############################################################################

@NM_LOG_COMPILER@
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
