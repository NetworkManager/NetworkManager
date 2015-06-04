if ENABLE_TESTS

include $(GLIB_MAKEFILE)

GLIB_GENERATED = nm-core-tests-enum-types.h nm-core-tests-enum-types.c
nm_core_tests_enum_types_sources = test-general-enums.h
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM

BUILT_SOURCES = $(GLIB_GENERATED)

certsdir = $(srcdir)/certs

AM_CPPFLAGS = \
	-I${top_srcdir}/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	-DTEST_CERT_DIR=\"$(certsdir)\"

noinst_PROGRAMS =		\
	test-compare		\
	test-crypto		\
	test-general		\
	test-keyfile		\
	test-secrets		\
	test-setting-8021x	\
	test-setting-dcb	\
	test-settings-defaults

LDADD = \
	$(top_builddir)/libnm-core/libnm-core.la \
	$(GLIB_LIBS)

@VALGRIND_RULES@
TESTS = $(noinst_PROGRAMS)

test_general_SOURCES = \
	test-general.c \
	test-general-enums.h \
	nm-core-tests-enum-types.c \
	nm-core-tests-enum-types.h

endif

# test-cert.p12 created with:
#
# openssl pkcs12 -export \
#	-in test_key_and_cert.pem \
#	-inkey test_key_and_cert.pem \
#	-certfile test_ca_cert.pem \
#	-name "test-pkcs12" \
#	-out test-cert.p12

EXTRA_DIST =                            \
	certs/ca-no-ending-newline.pem      \
	certs/pkcs8-decrypted.der           \
	certs/pkcs8-enc-key.pem             \
	certs/pkcs8-noenc-key.pem           \
	certs/test2_ca_cert.pem             \
	certs/test2-cert.p12                \
	certs/test2_key_and_cert.pem        \
	certs/test-aes-key.pem              \
	certs/test_ca_cert.der              \
	certs/test_ca_cert.pem              \
	certs/test-ca-cert.pem              \
	certs/test-cert.p12                 \
	certs/test_key_and_cert.pem         \
	certs/test-key-and-cert.pem         \
	certs/test-key-only-decrypted.der   \
	certs/test-key-only-decrypted.pem   \
	certs/test-key-only.pem

