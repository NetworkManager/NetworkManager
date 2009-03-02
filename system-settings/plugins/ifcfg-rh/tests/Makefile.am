SUBDIRS=network-scripts

INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/system-settings/plugins/ifcfg-rh

noinst_PROGRAMS = test-ifcfg-rh

test_ifcfg_rh_SOURCES = \
	test-ifcfg-rh.c

test_ifcfg_rh_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DTEST_DIR=\"$(abs_srcdir)/\"

test_ifcfg_rh_LDADD = \
	$(DBUS_LIBS) \
	$(top_builddir)/libnm-glib/libnm_glib.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/system-settings/plugins/ifcfg-rh/libifcfg-rh-io.la

if WITH_TESTS

check-local: test-ifcfg-rh
	$(abs_builddir)/test-ifcfg-rh

endif

