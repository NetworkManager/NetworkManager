if ENABLE_TESTS

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm \
	-I$(top_builddir)/libnm \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DTEST_NM_SERVICE=\"$(abs_top_srcdir)/tools/test-networkmanager-service.py\" \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

noinst_PROGRAMS = $(TESTS)

TESTS = test-nm-client test-remote-settings-client

test_nm_client_SOURCES = \
	common.c \
	common.h \
	test-nm-client.c

test_remote_settings_client_SOURCES = \
	common.c \
	common.h \
	test-remote-settings-client.c

TESTS_ENVIRONMENT = $(srcdir)/libnm-test-launch.sh

endif

EXTRA_DIST = libnm-test-launch.sh
