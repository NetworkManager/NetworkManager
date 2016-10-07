if ENABLE_TESTS

include $(top_srcdir)/nm.mk

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

noinst_PROGRAMS = test-ifcfg-rh test-ifcfg-rh-utils

test_ifcfg_rh_SOURCES = \
	test-ifcfg-rh.c \
	../nms-ifcfg-rh-reader.c \
	../shvar.c \
	../nms-ifcfg-rh-utils.c \
	../nms-ifcfg-rh-writer.c

test_ifcfg_rh_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

test_ifcfg_rh_utils_SOURCES = \
	test-ifcfg-rh-utils.c \
	../nms-ifcfg-rh-utils.c \
	../shvar.c

test_ifcfg_rh_utils_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@VALGRIND_RULES@
TESTS = test-ifcfg-rh-utils test-ifcfg-rh

check-local:
	$(call check_so_symbols,$(builddir)/../.libs/libnm-settings-plugin-ifcfg-rh.so)

endif

