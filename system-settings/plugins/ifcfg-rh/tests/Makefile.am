SUBDIRS=network-scripts

INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/system-settings/plugins/ifcfg-rh

noinst_PROGRAMS = test-ifcfg-rh test-ifcfg-rh-utils

test_ifcfg_rh_SOURCES = \
	test-ifcfg-rh.c

test_ifcfg_rh_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DTEST_IFCFG_DIR=\"$(abs_srcdir)\" \
	-DTEST_SCRATCH_DIR=\"$(abs_builddir)/\"

test_ifcfg_rh_LDADD = \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/system-settings/plugins/ifcfg-rh/libifcfg-rh-io.la \
	$(DBUS_LIBS)

test_ifcfg_rh_utils_SOURCES = \
	test-ifcfg-rh-utils.c

test_ifcfg_rh_utils_CPPFLAGS = \
	$(GLIB_CFLAGS)

test_ifcfg_rh_utils_LDADD = \
	$(top_builddir)/system-settings/plugins/ifcfg-rh/libifcfg-rh-io.la

if WITH_TESTS

check-local: test-ifcfg-rh
	$(abs_builddir)/test-ifcfg-rh-utils
	$(abs_builddir)/test-ifcfg-rh

endif

EXTRA_DIST = \
	iscsiadm-test-dhcp \
	iscsiadm-test-static \
	iscsiadm-test-bad-ipaddr \
	iscsiadm-test-bad-gateway \
	iscsiadm-test-bad-dns1 \
	iscsiadm-test-bad-dns2

