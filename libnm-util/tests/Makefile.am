if ENABLE_TESTS

SUBDIRS=certs

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DTEST_CERT_DIR=\"$(top_srcdir)/libnm-util/tests/certs/\"

noinst_PROGRAMS = \
	test-settings-defaults \
	test-crypto \
	test-secrets \
	test-general \
	test-setting-8021x \
	test-setting-dcb

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

check-local: test-crypto test-setting-8021x
# Private key and CA certificate in the same file (PEM)
	$(abs_builddir)/test-setting-8021x $(srcdir)/certs/test_key_and_cert.pem "test"

# Private key by itself (PEM)
	$(abs_builddir)/test-setting-8021x $(srcdir)/certs/test-key-only.pem "test"

# PKCS#8 private key by itself (PEM)
	$(abs_builddir)/test-setting-8021x $(srcdir)/certs/pkcs8-enc-key.pem "1234567890"

# Private key and CA certificate in the same file (pkcs12)
	$(abs_builddir)/test-setting-8021x $(srcdir)/certs/test-cert.p12 "test"

# Normal CA certificate
	$(abs_builddir)/test-crypto --cert $(srcdir)/certs/test_ca_cert.pem

# Another CA certificate
	$(abs_builddir)/test-crypto --cert $(srcdir)/certs/test2_ca_cert.pem

# Normal CA certificate (DER format)
	$(abs_builddir)/test-crypto --cert $(srcdir)/certs/test_ca_cert.der

# CA certificate without an ending newline
	$(abs_builddir)/test-crypto --cert $(srcdir)/certs/ca-no-ending-newline.pem

# Combined user cert and private key
	$(abs_builddir)/test-crypto --cert $(srcdir)/certs/test_key_and_cert.pem

# Another combined user cert and private key
	$(abs_builddir)/test-crypto --cert $(srcdir)/certs/test2_key_and_cert.pem

# Private key with 8 bytes of tail padding
	$(abs_builddir)/test-crypto --key \
		$(srcdir)/certs/test_key_and_cert.pem \
		"test" \
		$(srcdir)/certs/test-key-only-decrypted.der

# Private key only (not combined with a cert)
	$(abs_builddir)/test-crypto --key \
		$(srcdir)/certs/test-key-only.pem \
		"test" \
		$(srcdir)/certs/test-key-only-decrypted.der

# Private key with 6 bytes of tail padding
	$(abs_builddir)/test-crypto --key $(srcdir)/certs/test2_key_and_cert.pem "12345testing"

# PKCS#12 file
	$(abs_builddir)/test-crypto --p12 $(srcdir)/certs/test-cert.p12 "test"

# Another PKCS#12 file
	$(abs_builddir)/test-crypto --p12 $(srcdir)/certs/test2-cert.p12 "12345testing"

# PKCS#8 encrypted private key
	$(abs_builddir)/test-crypto --pkcs8 \
		$(srcdir)/certs/pkcs8-enc-key.pem \
		"1234567890"

# Private key with AES cipher
	$(abs_builddir)/test-crypto --key $(srcdir)/certs/test-aes-key.pem "test-aes-password"

TESTS = test-settings-defaults test-secrets test-general test-setting-dcb

endif
