if ENABLE_TESTS

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/libgsystem \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DTEST_NM_BIN=\"$(abs_srcdir)/test-fake-nm.py\" \
	-DTEST_RSS_BIN=\"$(abs_srcdir)/test-remote-settings-service.py\" \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

noinst_PROGRAMS = $(TESTS)

#@VALGRIND_RULES@
TESTS = test-nm-client test-remote-settings-client

TESTS_ENVIRONMENT = $(srcdir)/libnm-glib-test-launch.sh

####### NMClient and non-settings tests #######

test_nm_client_SOURCES = \
	test-nm-client.c

test_nm_client_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

####### remote settings client test #######

test_remote_settings_client_SOURCES = \
	test-remote-settings-client.c

test_remote_settings_client_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

###########################################

endif

EXTRA_DIST = test-fake-nm.py test-remote-settings-service.py libnm-glib-test-launch.sh
