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
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

test_crypto_SOURCES = \
	test-crypto.c

test_crypto_CPPFLAGS = \
	$(GLIB_CFLAGS)

test_crypto_LDADD = \
	$(top_builddir)/libnm-util/libtest-crypto.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS)


if WITH_TESTS

check-local: test-settings-defaults test-crypto
	$(abs_builddir)/test-settings-defaults

# Cert with 8 bytes of tail padding
	$(abs_builddir)/test-crypto \
		$(top_srcdir)/libnm-util/tests/certs/test_ca_cert.pem \
		$(top_srcdir)/libnm-util/tests/certs/test_key_and_cert.pem \
		$(top_srcdir)/libnm-util/tests/certs/test_key_and_cert.pem \
		"test" \
		$(top_srcdir)/libnm-util/tests/certs/test-cert.p12 \
		"test"

# Cert with only 6 bytes of tail padding
	$(abs_builddir)/test-crypto \
		$(top_srcdir)/libnm-util/tests/certs/test2_ca_cert.pem \
		$(top_srcdir)/libnm-util/tests/certs/test2_key_and_cert.pem \
		$(top_srcdir)/libnm-util/tests/certs/test2_key_and_cert.pem \
		"12345testing" \
		$(top_srcdir)/libnm-util/tests/certs/test2-cert.p12 \
		"12345testing"

endif

