if ENABLE_TESTS

SUBDIRS=network-scripts

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(srcdir)/../ \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DTEST_IFCFG_DIR=\"$(abs_srcdir)\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/\" \
	-DSYSCONFDIR=\"nonexistent\" \
	-DSBINDIR=\"nonexistent\"

AM_LDFLAGS = \
	$(GLIB_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)

noinst_PROGRAMS = test-ifcfg-rh

test_ifcfg_rh_SOURCES = \
	test-ifcfg-rh.c

test_ifcfg_rh_LDADD = \
	$(top_builddir)/src/settings/plugins/ifcfg-rh/libnms-ifcfg-rh-core.la \
	$(top_builddir)/src/libNetworkManager.la

@NM_LOG_COMPILER@
TESTS = test-ifcfg-rh

endif
