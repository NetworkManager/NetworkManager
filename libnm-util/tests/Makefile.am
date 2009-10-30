SUBDIRS=certs

INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util

noinst_PROGRAMS = test-settings-defaults test-crypto

test_settings_defaults_SOURCES = \
	test-settings-defaults.c

test_settings_defaults_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

test_settings_defaults_LDADD = \
	$(GLIB_LIBS) \
	$(DBUS_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la

test_crypto_SOURCES = \
	test-crypto.c

test_crypto_CPPFLAGS = \
	$(GLIB_CFLAGS)

test_crypto_LDADD = \
	$(GLIB_LIBS) \
	$(top_builddir)/libnm-util/libtest-crypto.la


if WITH_TESTS

check-local: test-settings-defaults test-crypto
	$(abs_builddir)/test-settings-defaults
	$(abs_builddir)/test-crypto \
		$(top_srcdir)/libnm-util/tests/certs/test_ca_cert.pem \
		$(top_srcdir)/libnm-util/tests/certs/test_key_and_cert.pem \
		$(top_srcdir)/libnm-util/tests/certs/test_key_and_cert.pem \
		"test" \
		$(top_srcdir)/libnm-util/tests/certs/test-cert.p12 \
		"test"

endif

