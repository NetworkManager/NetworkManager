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

check-local: test-settings-defaults test-crypto
	$(abs_builddir)/test-settings-defaults
	$(abs_builddir)/test-need-secrets

# Normal CA certificate
	$(abs_builddir)/test-crypto --cert \
		$(top_srcdir)/libnm-util/tests/certs/test_ca_cert.pem

# Another CA certificate
	$(abs_builddir)/test-crypto --cert \
		$(top_srcdir)/libnm-util/tests/certs/test2_ca_cert.pem

# CA certificate without an ending newline
	$(abs_builddir)/test-crypto --cert \
		$(top_srcdir)/libnm-util/tests/certs/ca-no-ending-newline.pem

# Combined user cert and private key
	$(abs_builddir)/test-crypto --cert \
		$(top_srcdir)/libnm-util/tests/certs/test_key_and_cert.pem

# Another combined user cert and private key
	$(abs_builddir)/test-crypto --cert \
		$(top_srcdir)/libnm-util/tests/certs/test2_key_and_cert.pem

# Private key with 8 bytes of tail padding
	$(abs_builddir)/test-crypto --key \
		$(top_srcdir)/libnm-util/tests/certs/test_key_and_cert.pem \
		"test"

# Private key with 6 bytes of tail padding
	$(abs_builddir)/test-crypto --key \
		$(top_srcdir)/libnm-util/tests/certs/test2_key_and_cert.pem \
		"12345testing"

# PKCS#12 file
	$(abs_builddir)/test-crypto --p12 \
		$(top_srcdir)/libnm-util/tests/certs/test-cert.p12 \
		"test"

# Another PKCS#12 file
	$(abs_builddir)/test-crypto --p12 \
		$(top_srcdir)/libnm-util/tests/certs/test2-cert.p12 \
		"12345testing"

endif

