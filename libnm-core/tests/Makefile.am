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
	test-compare		\
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

TESTS = $(noinst_PROGRAMS)

endif
