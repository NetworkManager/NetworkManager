SUBDIRS=certs

INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util

noinst_PROGRAMS = test-settings-defaults test-crypto test-need-secrets

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

test_need_secrets_SOURCES = \
	test-need-secrets.c

test_need_secrets_CPPFLAGS = \
	-DTEST_CERT_DIR=\"$(top_srcdir)/libnm-util/tests/certs/\" \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

test_need_secrets_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

if WITH_TESTS

check-local: test-settings-defaults test-crypto test-need-secrets
	$(abs_builddir)/test-settings-defaults
	$(abs_builddir)/test-need-secrets

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

