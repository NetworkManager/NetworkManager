INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/libnm-glib

noinst_PROGRAMS = test-remote-settings-client

####### remote settings client test #######

test_remote_settings_client_SOURCES = \
	test-remote-settings-client.c

test_remote_settings_client_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

test_remote_settings_client_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib-test.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

###########################################

TEST_RSS_BIN = test-remote-settings-service.py

EXTRA_DIST = $(TEST_RSS_BIN)

if WITH_TESTS

check-local: test-remote-settings-client
	$(abs_builddir)/test-remote-settings-client $(abs_srcdir) $(TEST_RSS_BIN)

endif

