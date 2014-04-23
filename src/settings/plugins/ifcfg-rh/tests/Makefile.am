if ENABLE_TESTS

SUBDIRS=network-scripts

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/logging \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/src/posix-signals \
	-I$(srcdir)/../ \
	-DG_LOG_DOMAIN=\""NetworkManager-ifcfg-rh"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DTEST_IFCFG_DIR=\"$(abs_srcdir)\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/\" \
	-DSYSCONFDIR=\"nonexistent\" \
	-DSBINDIR=\"nonexistent\"

AM_LDFLAGS = \
	$(GLIB_LIBS) \
	$(DBUS_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)

AM_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la

noinst_PROGRAMS = test-ifcfg-rh test-ifcfg-rh-utils

test_ifcfg_rh_SOURCES = \
	test-ifcfg-rh.c \
	../errors.c \
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
	$(AM_LDADD)

TESTS = test-ifcfg-rh-utils test-ifcfg-rh

EXTRA_DIST = \
	iscsiadm-test-dhcp \
	iscsiadm-test-static \
	iscsiadm-test-bad-ipaddr \
	iscsiadm-test-bad-gateway \
	iscsiadm-test-bad-dns1 \
	iscsiadm-test-bad-dns2 \
	iscsiadm-test-bad-entry \
	iscsiadm-test-bad-record

endif

