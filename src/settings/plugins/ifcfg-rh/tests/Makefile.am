if ENABLE_TESTS

SUBDIRS=network-scripts

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(srcdir)/../ \
	-DG_LOG_DOMAIN=\""NetworkManager-ifcfg-rh"\" \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DTEST_IFCFG_DIR=\"$(abs_srcdir)\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/\" \
	-DSYSCONFDIR=\"nonexistent\" \
	-DSBINDIR=\"nonexistent\"

AM_LDFLAGS = \
	$(GLIB_LIBS) \
	$(DBUS_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)

noinst_PROGRAMS = test-ifcfg-rh test-ifcfg-rh-utils

test_ifcfg_rh_SOURCES = \
	test-ifcfg-rh.c \
	../reader.c \
	../shvar.c \
	../utils.c \
	../writer.c

test_ifcfg_rh_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

test_ifcfg_rh_utils_SOURCES = \
	test-ifcfg-rh-utils.c \
	../utils.c \
	../shvar.c

test_ifcfg_rh_utils_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@VALGRIND_RULES@
TESTS = test-ifcfg-rh-utils test-ifcfg-rh

endif

