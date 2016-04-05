if ENABLE_TESTS

AM_CPPFLAGS = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DBUILD_DIR=\"$(abs_builddir)\" \
	-DTEST_CERT_DIR=\"$(top_srcdir)/libnm-core/tests/certs/\"

@VALGRIND_RULES@
TESTS = \
	test-settings-defaults \
	test-crypto \
	test-secrets \
	test-general \
	test-setting-8021x \
	test-setting-dcb

noinst_PROGRAMS = \
	$(TESTS) \
	test-libnm-linking

test_settings_defaults_SOURCES = \
	test-settings-defaults.c

test_settings_defaults_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

test_crypto_SOURCES = \
	test-crypto.c

test_crypto_LDADD = \
	$(top_builddir)/libnm-util/libtest-crypto.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS)

test_secrets_SOURCES = \
	test-secrets.c

test_secrets_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

test_general_SOURCES = \
	test-general.c

test_general_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

test_general_DEPENDENCIES = test-libnm-linking

test_setting_8021x_SOURCES = \
	test-setting-8021x.c

test_setting_8021x_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

test_setting_dcb_SOURCES = \
	test-setting-dcb.c

test_setting_dcb_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

test_libnm_linking_SOURCES = \
	test-libnm-linking.c

test_libnm_linking_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

endif
