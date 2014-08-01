if ENABLE_TESTS

certsdir = $(top_srcdir)/libnm-util/tests/certs

AM_CPPFLAGS = \
	-I${top_srcdir}/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DTEST_CERT_DIR=\"$(certsdir)\"

noinst_PROGRAMS =		\
	test-crypto		\
	test-general		\
	test-secrets		\
	test-setting-8021x	\
	test-setting-dcb	\
	test-settings-defaults

LDADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

check-local: test-crypto test-setting-8021x
# Private key and CA certificate in the same file (PEM)
	$(abs_builddir)/test-setting-8021x $(certsdir)/test_key_and_cert.pem "test"

# Private key by itself (PEM)
	$(abs_builddir)/test-setting-8021x $(certsdir)/test-key-only.pem "test"

# PKCS#8 private key by itself (PEM)
	$(abs_builddir)/test-setting-8021x $(certsdir)/pkcs8-enc-key.pem "1234567890"

# Private key and CA certificate in the same file (pkcs12)
	$(abs_builddir)/test-setting-8021x $(certsdir)/test-cert.p12 "test"

# Normal CA certificate
	$(abs_builddir)/test-crypto --cert $(certsdir)/test_ca_cert.pem

# Another CA certificate
	$(abs_builddir)/test-crypto --cert $(certsdir)/test2_ca_cert.pem

# Normal CA certificate (DER format)
	$(abs_builddir)/test-crypto --cert $(certsdir)/test_ca_cert.der

# CA certificate without an ending newline
	$(abs_builddir)/test-crypto --cert $(certsdir)/ca-no-ending-newline.pem

# Combined user cert and private key
	$(abs_builddir)/test-crypto --cert $(certsdir)/test_key_and_cert.pem

# Another combined user cert and private key
	$(abs_builddir)/test-crypto --cert $(certsdir)/test2_key_and_cert.pem

# Private key with 8 bytes of tail padding
	$(abs_builddir)/test-crypto --key \
		$(certsdir)/test_key_and_cert.pem \
		"test" \
		$(certsdir)/test-key-only-decrypted.der

# Private key only (not combined with a cert)
	$(abs_builddir)/test-crypto --key \
		$(certsdir)/test-key-only.pem \
		"test" \
		$(certsdir)/test-key-only-decrypted.der

# Private key with 6 bytes of tail padding
	$(abs_builddir)/test-crypto --key $(certsdir)/test2_key_and_cert.pem "12345testing"

# PKCS#12 file
	$(abs_builddir)/test-crypto --p12 $(certsdir)/test-cert.p12 "test"

# Another PKCS#12 file
	$(abs_builddir)/test-crypto --p12 $(certsdir)/test2-cert.p12 "12345testing"

# PKCS#8 encrypted private key
	$(abs_builddir)/test-crypto --pkcs8 \
		$(certsdir)/pkcs8-enc-key.pem \
		"1234567890"

# Private key with AES cipher
	$(abs_builddir)/test-crypto --key $(certsdir)/test-aes-key.pem "test-aes-password"

TESTS = test-settings-defaults test-secrets test-general test-setting-dcb

endif
