INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/supplicant-manager

noinst_PROGRAMS = test-supplicant-config

test_supplicant_config_SOURCES = \
	test-supplicant-config.c

test_supplicant_config_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

test_supplicant_config_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/src/supplicant-manager/libsupplicant-manager.la \
	$(DBUS_LIBS)

if WITH_TESTS

check-local: test-supplicant-config
	$(abs_builddir)/test-supplicant-config

endif

