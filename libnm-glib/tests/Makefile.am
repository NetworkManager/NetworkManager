if ENABLE_TESTS

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

noinst_PROGRAMS = test-nm-client test-remote-settings-client

####### NMClient and non-settings tests #######

test_nm_client_SOURCES = \
	test-nm-client.c

test_nm_client_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib-test.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

####### remote settings client test #######

test_remote_settings_client_SOURCES = \
	test-remote-settings-client.c

test_remote_settings_client_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib-test.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

###########################################

TEST_NM_BIN = test-fake-nm.py
TEST_RSS_BIN = test-remote-settings-service.py

EXTRA_DIST = $(TEST_RSS_BIN) $(TEST_NM_BIN)

check-local: test-nm-client test-remote-settings-client
	if test -z "$$DBUS_SESSION_BUS_ADDRESS" ; then \
	    dbus-launch --exit-with-session $(abs_builddir)/test-nm-client $(abs_srcdir) $(TEST_NM_BIN); \
	    dbus-launch --exit-with-session $(abs_builddir)/test-remote-settings-client $(abs_srcdir) $(TEST_RSS_BIN); \
	else \
	    $(abs_builddir)/test-nm-client $(abs_srcdir) $(TEST_NM_BIN); \
	    $(abs_builddir)/test-remote-settings-client $(abs_srcdir) $(TEST_RSS_BIN); \
	fi;

endif
