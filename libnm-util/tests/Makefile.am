INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util

noinst_PROGRAMS = test-settings-defaults

test_settings_defaults_SOURCES = \
	test-settings-defaults.c

test_settings_defaults_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

test_settings_defaults_LDADD = \
	$(GTHREAD_LIBS) \
	$(DBUS_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la

if WITH_TESTS

check-local: test-settings-defaults
	$(abs_builddir)/test-settings-defaults

endif

